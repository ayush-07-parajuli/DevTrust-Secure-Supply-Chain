# DevTrust Security Overview

## Project Purpose

DevTrust is a secure supply chain verification system designed to ensure that software artifacts submitted by developers remain authentic and untampered throughout the review workflow.

The system demonstrates practical implementation of modern cryptographic protections including digital signatures, hashing, and encrypted key storage.

---

## Security Goals

The system aims to enforce the following security properties:

- **Integrity** – Prevent unauthorized modification of submitted code artifacts
- **Authenticity** – Ensure that submitted artifacts originate from the claimed developer
- **Non-repudiation** – Prevent developers from denying authorship of submitted artifacts
- **Confidentiality** – Protect developer private keys from unauthorized access
- **Traceability** – Maintain verifiable audit logs for security events

---

## Cryptographic Mechanisms

### RSA Digital Signatures

Each developer receives a unique **RSA-2048 key pair** during registration.

The private key is used to sign submitted artifacts using **RSA-PSS with SHA-256**.

This ensures:

- Developer identity binding
- Artifact integrity
- Non-repudiation

---

### SHA-256 Integrity Verification

When a file is submitted:

1. The file is hashed using **SHA-256**
2. The hash is stored in the database
3. During approval, the file is hashed again
4. The hashes are compared to detect tampering

If the hash does not match, approval is blocked.

---

### AES-256-GCM Private Key Protection

Developer private keys are encrypted at rest using **AES-256-GCM**.

Key derivation uses:

- **PBKDF2-HMAC-SHA256**
- **200,000 iterations**
- **Random 16-byte salt**

AES-GCM provides both:

- Confidentiality
- Integrity protection

---

## Secure Workflow

1. Developer registers and receives cryptographic keys
2. Developer signs artifact before submission
3. Artifact is stored in the **staging environment**
4. Senior reviewer verifies signature and hash
5. Verified artifacts move to **production-ready storage**

---

## Audit Logging

The system records security events including:

- Login attempts
- File submissions
- Approval and rejection actions
- Security validation failures

This provides **forensic traceability and accountability**.

---

## Conclusion

DevTrust demonstrates how practical cryptographic mechanisms can be integrated into a software development workflow to protect the software supply chain from tampering and unauthorized modification.