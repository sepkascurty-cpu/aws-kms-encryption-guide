# Quiz: AWS KMS Encryption 🔐

Test what you learned from the [README](README.md). Answers are hidden — click to reveal.

---

## 1. What is envelope encryption?

A. Encrypting an envelope that contains a USB stick with the key on it
B. KMS encrypts a data key, and the data key encrypts your data
C. Encrypting data twice with the same key for extra safety
D. A KMS feature that encrypts S3 buckets automatically

<details>
<summary>Answer</summary>

**B.** KMS only ever sees the small (32-byte) data key — your actual data is encrypted locally with that data key (e.g. AES-256-GCM). The encrypted data key is stored next to the ciphertext.

</details>

---

## 2. You call `Decrypt` and get `AccessDenied`, even though your IAM role has `kms:Decrypt`. What should you check FIRST?

A. The IAM policy — it must be wrong
B. The key policy — IAM alone is never enough for KMS
C. The AWS region — you must be in us-east-1
D. Your password — it probably expired

<details>
<summary>Answer</summary>

**B.** The **key policy** is the only policy that can grant access to a KMS key. If the key policy doesn't allow your principal, no IAM policy can override that. Check the key policy first, then IAM.

</details>

---

## 3. You enable automatic key rotation on a CMK. What happens to data encrypted with the OLD key version?

A. It becomes unreadable — you must re-encrypt everything
B. It stays decryptable — KMS keeps every old key version
C. It is automatically re-encrypted with the new version
D. It is deleted after 30 days

<details>
<summary>Answer</summary>

**B.** Rotation only changes the key material used for *new* encryptions. KMS retains all previous versions, so old ciphertext still decrypts. Rotation is safe to enable everywhere.

</details>

---

## 4. What does an encryption context do?

A. It makes encryption faster by adding context to the algorithm
B. It binds ciphertext to its purpose — decrypting with a different context fails
C. It stores the plaintext key so you can recover it later
D. Nothing — it's just a label for the AWS console

<details>
<summary>Answer</summary>

**B.** The encryption context is cryptographically bound to the ciphertext. `Decrypt` with a different context fails, even with full KMS access — and the context appears in CloudTrail, so it doubles as an audit trail.

</details>

---

## 5. A developer schedules a CMK for deletion with the default 30-day window. During those 30 days, what happens?

A. Nothing changes — the key works normally until day 30
B. The key is disabled immediately and all data encrypted with it becomes unreadable
C. Only new encryptions fail; old data still decrypts
D. AWS automatically backs the key up to another Region

<details>
<summary>Answer</summary>

**B.** During the waiting period the key is **disabled** — every `Encrypt` and `Decrypt` call fails, so all data protected by that key is unreadable. You can cancel the deletion during the window, but after it closes there is no recovery. Always alarm on `ScheduleKeyDeletion`.

</details>

---

**Score yourself:** 5/5 — you're ready to own KMS in production. 3–4 — re-read the rotation and key-policy sections. 0–2 — start again at the top of the README, it's worth it. 🔐
