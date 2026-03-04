# DevTrust – Secure Supply Chain Verifier

DevTrust is a desktop-based secure code review workflow system developed for the ST6051CEM Practical Cryptography module.

The application implements cryptographic protections to secure a developer-to-reviewer supply chain using RSA digital signatures, SHA-256 hashing, AES-256-GCM encryption, and structured audit logging.

---

## 🔐 Security Features

- RSA-2048 Digital Signatures (RSA-PSS with SHA-256)
- SHA-256 Integrity Hashing
- AES-256-GCM Private Key Encryption at Rest
- PBKDF2-HMAC-SHA256 Key Derivation (200,000 iterations)
- Cryptographic Verification Enforcement Before Approval
- Structured Audit Logging
- Secure Staging and Production File Workflow

---

## 🏗 System Architecture

The application consists of:

- GUI Layer (customtkinter)
- Cryptographic Engine (crypto_engine.py)
- Database Layer (SQLite)
- File Storage Workflow (staging → verification → prod_ready)

---

## 📂 Directory Structure

```
keys/               → Encrypted private keys (.enc)
database/           → SQLite database (devtrust.db)
uploads/staging/    → Untrusted submission area
uploads/prod_ready/ → Approved artefacts
uploads/review_temp/→ Temporary reviewer copies
```

---

## ▶ Running the Application

1. Install dependencies:
   ```
   pip install cryptography customtkinter
   ```

2. Run:
   ```
   python main.py
   ```

---

## ⚠ Educational Disclaimer

This project is developed for academic demonstration purposes only and is not production-ready software.

---

## 📘 Module Information

Module: ST6051CEM – Practical Cryptography  
Project: DevTrust – Secure Supply Chain Verifier