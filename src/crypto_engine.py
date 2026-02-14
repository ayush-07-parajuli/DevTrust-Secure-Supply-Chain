from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os

class CryptoEngine:
    # --- AES-at-rest settings ---
    _MAGIC = b"DEVTRUST-KEY-V1"  # file header to identify our encrypted key format
    _SALT_LEN = 16
    _NONCE_LEN = 12  # recommended size for AESGCM
    _KDF_ITERS = 200_000  # strong enough for coursework; adjust if needed

    # ---------------------------
    # Existing RSA key generation
    # ---------------------------
    @staticmethod
    def generate_key_pair(password: str):
        # RSA 2048-bit Key Generation
        private_key = rsa.generate_private_key(65537, 2048, default_backend())

        # Keep this exactly as you had it: password-protected PKCS8 PEM
        pem_private = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode())
        )

        pem_public = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_private, pem_public

    # ---------------------------
    # Existing signing logic
    # ---------------------------
    @staticmethod
    def sign_data(file_path, private_key_pem: bytes, password: str):
        private_key = serialization.load_pem_private_key(
            private_key_pem, password=password.encode(), backend=default_backend()
        )

        with open(file_path, "rb") as f:
            data = f.read()

        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    # ==========================================================
    # NEW: Symmetric crypto (AES-256-GCM) to protect private keys
    # ==========================================================

    @staticmethod
    def _derive_aes_key_from_password(password: str, salt: bytes) -> bytes:
        """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=salt,
            iterations=CryptoEngine._KDF_ITERS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_and_store_private_key(email: str, private_key_pem: bytes, password: str, keys_dir: str = "keys"):
        """
        Encrypt the (already PKCS8-password-protected) PEM again using AES-256-GCM
        and store it as keys/<email>_private.enc
        """
        os.makedirs(keys_dir, exist_ok=True)

        salt = os.urandom(CryptoEngine._SALT_LEN)
        key = CryptoEngine._derive_aes_key_from_password(password, salt)
        aesgcm = AESGCM(key)

        nonce = os.urandom(CryptoEngine._NONCE_LEN)
        ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)

        out_path = os.path.join(keys_dir, f"{email}_private.enc")
        with open(out_path, "wb") as f:
            # Format: MAGIC || salt || nonce || ciphertext
            f.write(CryptoEngine._MAGIC + b"\n")
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        return out_path

    @staticmethod
    def load_private_key_pem(email: str, password: str, keys_dir: str = "keys") -> bytes:
        """
        Load and decrypt keys/<email>_private.enc using AES-256-GCM.
        Backward-compatible: if .enc doesn't exist, fall back to old .pem file.
        """
        enc_path = os.path.join(keys_dir, f"{email}_private.enc")
        pem_path = os.path.join(keys_dir, f"{email}_private.pem")

        # Backward compatibility: old storage
        if not os.path.exists(enc_path):
            with open(pem_path, "rb") as f:
                return f.read()

        with open(enc_path, "rb") as f:
            first_line = f.readline().rstrip(b"\n")
            if first_line != CryptoEngine._MAGIC:
                raise ValueError("Invalid private key container format.")

            salt = f.read(CryptoEngine._SALT_LEN)
            nonce = f.read(CryptoEngine._NONCE_LEN)
            ciphertext = f.read()

        key = CryptoEngine._derive_aes_key_from_password(password, salt)
        aesgcm = AESGCM(key)

        # returns the original PEM bytes (still PKCS8 password-protected inside)
        return aesgcm.decrypt(nonce, ciphertext, None)
