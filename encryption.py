"""
encryption.py — Encryption Module for Password Manager

Handles all encryption and decryption operations using Fernet symmetric
encryption. Derives the encryption key from the master password using
PBKDF2-HMAC-SHA256 so that no key file needs to be stored on disk.

Security notes:
- The Fernet key is derived at login and held only in memory during the session.
- A persistent 16-byte salt is stored in data/salt.bin (generated on first run).
- PBKDF2 uses 200,000 iterations to make brute-force attacks expensive.
- Fernet automatically handles IV generation and HMAC verification.
"""

import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

# ── Configuration ──────────────────────────────────────────────────────────────

# Directory where runtime data files are stored
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Path to the persistent salt file
SALT_FILE = os.path.join(DATA_DIR, "salt.bin")

# PBKDF2 parameters (matching Week 3 report specification)
PBKDF2_ITERATIONS = 200_000
PBKDF2_KEY_LENGTH = 32  # 32 bytes → 256-bit key for Fernet (base64-encoded)


# ── Salt Management ────────────────────────────────────────────────────────────

def get_or_create_salt() -> bytes:
    """
    Read the encryption salt from data/salt.bin.
    If the file does not exist, generate a new 16-byte random salt and save it.

    Returns:
        bytes: 16-byte salt used for PBKDF2 key derivation.

    Raises:
        OSError: If the data directory cannot be created or the salt file
                 cannot be read/written.
    """
    # Ensure the data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        if len(salt) != 16:
            raise ValueError(
                "Salt file is corrupted (expected 16 bytes, "
                f"got {len(salt)}). Delete data/salt.bin and re-setup."
            )
        return salt

    # First run — generate a fresh salt
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt


# ── Key Derivation ─────────────────────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a Fernet-compatible encryption key from the master password.

    Uses PBKDF2-HMAC-SHA256 with 200,000 iterations to produce a 32-byte key,
    then URL-safe base64-encodes it (as required by Fernet).

    Args:
        master_password: The user's master password (plaintext string).
        salt: 16-byte salt value (from get_or_create_salt()).

    Returns:
        bytes: 44-byte URL-safe base64-encoded key suitable for Fernet().
    """
    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        iterations=PBKDF2_ITERATIONS,
        dklen=PBKDF2_KEY_LENGTH,
    )
    # Fernet expects a URL-safe base64-encoded 32-byte key
    return base64.urlsafe_b64encode(raw_key)


# ── Encrypt / Decrypt ──────────────────────────────────────────────────────────

def encrypt_password(plaintext: str, master_password: str) -> bytes:
    """
    Encrypt a plaintext password string using Fernet.

    The encryption key is derived from the master password + stored salt.
    Fernet automatically generates a random IV for each call, so encrypting
    the same plaintext twice will produce different ciphertext.

    Args:
        plaintext: The password to encrypt.
        master_password: The user's master password (for key derivation).

    Returns:
        bytes: Fernet token (encrypted password) suitable for BLOB storage.

    Raises:
        ValueError: If plaintext or master_password is empty.
    """
    if not plaintext:
        raise ValueError("Cannot encrypt an empty password.")
    if not master_password:
        raise ValueError("Master password is required for encryption.")

    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    return fernet.encrypt(plaintext.encode("utf-8"))


def decrypt_password(token: bytes, master_password: str) -> str:
    """
    Decrypt a Fernet token back to the original plaintext password.

    Args:
        token: The encrypted Fernet token (bytes, as stored in the database).
        master_password: The user's master password (for key derivation).

    Returns:
        str: The decrypted plaintext password.

    Raises:
        InvalidToken: If the token is corrupted or the master password is wrong.
        ValueError: If token or master_password is empty.
    """
    if not token:
        raise ValueError("Cannot decrypt an empty token.")
    if not master_password:
        raise ValueError("Master password is required for decryption.")

    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(token).decode("utf-8")
