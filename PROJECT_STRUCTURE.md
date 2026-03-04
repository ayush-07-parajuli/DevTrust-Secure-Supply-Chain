# DevTrust Project Structure

## Overview

This document describes the directory structure of the DevTrust secure supply chain verifier. The project separates cryptographic logic, database management, and application interface components to maintain modularity and security.

---

## Root Directory

main.py  
Main application entry point.  
Implements GUI workflow for registration, login, submission, and artifact review.

requirements.txt  
Defines project dependencies including cryptography and customtkinter.

---

## Source Modules

src/crypto_engine.py  
Handles cryptographic operations including:

- RSA-2048 key generation
- RSA-PSS digital signature creation
- Signature verification
- AES-256-GCM private key encryption
- PBKDF2-HMAC-SHA256 key derivation

src/database_manager.py  
Handles database operations including:

- User registration
- Public key storage
- File submission records
- Signature and hash storage
- Audit logging

---

## Security Directories

keys/  
Stores encrypted private keys (.enc files).

database/  
Contains the SQLite database file used for storing system records.

uploads/staging/  
Temporary storage for newly submitted artifacts awaiting review.

uploads/prod_ready/  
Contains artifacts that have passed verification and approval.

uploads/review_temp/  
Temporary isolated copy used during reviewer inspection.

---

## Security Design Notes

The separation of directories ensures that:

- Unverified files cannot directly reach production storage
- Private keys remain encrypted at rest
- Review operations occur on isolated copies of files
- Audit logs maintain traceability of security events