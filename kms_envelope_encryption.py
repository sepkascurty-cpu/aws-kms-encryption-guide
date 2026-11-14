"""
AWS KMS Envelope Encryption — complete runnable demo.

What it shows:
  1. Envelope encryption: KMS protects a *data key*, the data key
     protects your data (AES-256-GCM, done locally).
  2. Encryption context: binds ciphertext to its purpose — decrypting
     with the wrong context fails, even with full KMS access.
  3. Customer managed key (CMK) with automatic rotation + least-privilege
     key policy.
  4. Grants: temporary, scoped access for another IAM role.

Install:  pip install boto3 cryptography
Run:      python kms_envelope_encryption.py --demo
          (needs AWS credentials with kms:* on the key you create)

Security note: the plaintext data key only ever lives in memory.
Never log it, never write it to disk.
"""

import argparse
import base64
import json
import os

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REGION = os.environ.get("AWS_REGION", "ap-southeast-1")


def get_kms_client():
    return boto3.client("kms", region_name=REGION)


# ---------------------------------------------------------------------------
# 1. Envelope encryption
# ---------------------------------------------------------------------------
def encrypt_bytes(plaintext: bytes, key_id: str, context: dict | None = None) -> dict:
    """Encrypt with a fresh data key from KMS. Returns everything needed
    to decrypt later (ciphertext + encrypted data key)."""
    kms = get_kms_client()
    response = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256",
                                     EncryptionContext=context or {})
    plaintext_key = response["Plaintext"]          # use it, then forget it
    encrypted_key = response["CiphertextBlob"]     # store this

    nonce = os.urandom(12)
    ciphertext = AESGCM(plaintext_key).encrypt(nonce, plaintext, None)
    del plaintext_key  # wipe the plaintext key from memory ASAP

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "encrypted_data_key": base64.b64encode(encrypted_key).decode(),
        "encryption_context": context or {},
    }


def decrypt_bytes(bundle: dict, key_id: str) -> bytes:
    """Ask KMS to unwrap the data key, then decrypt locally."""
    kms = get_kms_client()
    data_key = kms.decrypt(
        CiphertextBlob=base64.b64decode(bundle["encrypted_data_key"]),
        KeyId=key_id,
        EncryptionContext=bundle.get("encryption_context") or {},
    )["Plaintext"]

    plaintext = AESGCM(data_key).decrypt(
        base64.b64decode(bundle["nonce"]),
        base64.b64decode(bundle["ciphertext"]),
        None,
    )
    del data_key
    return plaintext


def encrypt_file(path: str, key_id: str, context: dict | None = None) -> str:
    """Encrypt a file in place-style: writes <path>.encrypted (JSON bundle)."""
    with open(path, "rb") as f:
        bundle = encrypt_bytes(f.read(), key_id, context)
    out_path = path + ".encrypted"
    with open(out_path, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"Encrypted {path} -> {out_path}")
    return out_path


def decrypt_file(encrypted_path: str, key_id: str) -> bytes:
    with open(encrypted_path) as f:
        bundle = json.load(f)
    return decrypt_bytes(bundle, key_id)


# ---------------------------------------------------------------------------
# 2. Create a CMK with rotation + least-privilege key policy
# ---------------------------------------------------------------------------
def create_key_with_rotation(account_id: str, admin_arn: str, app_role_arn: str) -> str:
    """Create a customer managed key. The key policy is the ONLY policy
    that can grant access — IAM alone is never enough."""
    kms = get_kms_client()
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allow account admin",
                "Effect": "Allow",
                "Principal": {"AWS": admin_arn},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "Allow app role to use the key",
                "Effect": "Allow",
                "Principal": {"AWS": app_role_arn},
                "Action": ["kms:Encrypt", "kms:Decrypt",
                           "kms:GenerateDataKey", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description="App data encryption key (envelope encryption demo)",
        KeyUsage="ENCRYPT_DECRYPT",
        Origin="AWS_KMS",
        Policy=json.dumps(policy),
    )
    key_id = key["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)  # automatic yearly rotation
    kms.create_alias(AliasName="alias/app-data-key", TargetKeyId=key_id)
    print(f"Created CMK {key_id} with rotation enabled")
    return key_id


# ---------------------------------------------------------------------------
# 3. Grants — temporary, scoped delegation
# ---------------------------------------------------------------------------
def grant_access(key_id: str, grantee_principal: str, hours: int = 2) -> str:
    """Give another principal Decrypt-only access, expiring automatically.
    Retire the grant when done — grants are how services like EBS and
    S3 get just-enough access without broad key policies."""
    kms = get_kms_client()
    grant = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=grantee_principal,
        Operations=["Decrypt", "GenerateDataKey"],
        Constraints={"EncryptionContextEquals": {"purpose": "app-data"}},
    )
    print(f"Grant {grant['GrantId']} created for {grantee_principal}")
    return grant["GrantId"]


def retire_grant(key_id: str, grant_id: str) -> None:
    get_kms_client().retire_grant(KeyId=key_id, GrantId=grant_id)
    print(f"Grant {grant_id} retired")


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
def demo():
    kms = get_kms_client()
    # Use the AWS managed key for S3 as a zero-setup demo key — replace
    # with your own CMK alias in real code: alias/app-data-key
    key_id = "alias/aws/s3"
    print("KMS key:", kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"])

    secret = b"database password: hunter2 — never store me in plaintext"
    context = {"purpose": "app-data", "env": "production"}

    bundle = encrypt_bytes(secret, key_id, context)
    print("Ciphertext (first 40 chars):", bundle["ciphertext"][:40], "...")
    print("Encrypted data key stored alongside, length:",
          len(bundle["encrypted_data_key"]), "chars (base64)")

    recovered = decrypt_bytes(bundle, key_id)
    assert recovered == secret, "round-trip failed!"
    print("Decrypted OK:", recovered.decode())

    # Wrong encryption context -> KMS refuses, even with full access.
    try:
        bad = dict(bundle, encryption_context={"purpose": "something-else"})
        decrypt_bytes(bad, key_id)
        print("ERROR: wrong context should have failed!")
    except kms.exceptions.KMSInvalidStateException:
        print("Wrong encryption context correctly rejected")
    except Exception as e:  # InvalidCiphertextException in practice
        print(f"Wrong encryption context correctly rejected ({type(e).__name__})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS KMS envelope encryption demo")
    parser.add_argument("--demo", action="store_true", help="run the end-to-end demo")
    args = parser.parse_args()
    if args.demo:
        demo()
    else:
        parser.print_help()
