"""
auth.py — Authentication Module for Password Manager

Handles master password setup (first-run) and login verification.
The master password is never stored — only its salted SHA-256 hash is
persisted in data/master.hash.

Security notes:
- The hash is computed as SHA-256(password_bytes + salt_bytes) to prevent
  rainbow-table attacks.
- Password must be at least 6 characters long (configurable via MIN_PASSWORD_LENGTH).
- This module does NOT handle encryption keys — that is done in encryption.py.
"""

import os
import hashlib

from encryption import get_or_create_salt

# ── Configuration ──────────────────────────────────────────────────────────────

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
MASTER_HASH_FILE = os.path.join(DATA_DIR, "master.hash")
MIN_PASSWORD_LENGTH = 6


# ── Helpers ────────────────────────────────────────────────────────────────────

def _hash_password(password: str, salt: bytes) -> str:
    """
    Compute a salted SHA-256 hash of the given password.

    Args:
        password: The plaintext password string.
        salt: The salt bytes (from encryption.get_or_create_salt()).

    Returns:
        str: Hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(password.encode("utf-8") + salt).hexdigest()


# ── Public API ─────────────────────────────────────────────────────────────────

def is_first_run() -> bool:
    """
    Check whether the application is being run for the first time.

    Returns:
        True if data/master.hash does not exist (no master password set yet).
    """
    return not os.path.exists(MASTER_HASH_FILE)


def setup_master_password(password: str) -> tuple[bool, str]:
    """
    Set up a new master password (first-run only).

    Validates the password, hashes it with SHA-256 + salt, and saves the
    hash to data/master.hash.

    Args:
        password: The chosen master password.

    Returns:
        tuple[bool, str]: (success, message).
            On success: (True, "Master password set successfully.")
            On failure: (False, "<reason>").
    """
    # Validation
    if not password or not password.strip():
        return False, "Password cannot be empty."

    if len(password) < MIN_PASSWORD_LENGTH:
        return (
            False,
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.",
        )

    # Ensure salt exists (creates it if first run)
    salt = get_or_create_salt()

    # Hash and persist
    os.makedirs(DATA_DIR, exist_ok=True)
    password_hash = _hash_password(password, salt)
    with open(MASTER_HASH_FILE, "w", encoding="utf-8") as f:
        f.write(password_hash)

    return True, "Master password set successfully."


def verify_master_password(entered_password: str) -> bool:
    """
    Verify an entered password against the stored master hash.

    Args:
        entered_password: The password the user typed at login.

    Returns:
        True if the hash matches the stored value; False otherwise.

    Raises:
        FileNotFoundError: If master.hash does not exist (should not happen
            if is_first_run() was checked first).
    """
    if not entered_password:
        return False

    if not os.path.exists(MASTER_HASH_FILE):
        raise FileNotFoundError(
            "Master password has not been set up yet. "
            "Run the application and complete the setup screen first."
        )

    salt = get_or_create_salt()
    computed_hash = _hash_password(entered_password, salt)

    with open(MASTER_HASH_FILE, "r", encoding="utf-8") as f:
        stored_hash = f.read().strip()

    return computed_hash == stored_hash


def reset_master_password() -> None:
    """
    Delete the stored master hash file.
    This forces a first-run setup on the next launch.

    WARNING: This does NOT re-encrypt existing vault data. All passwords
    encrypted with the old master password will become inaccessible.
    """
    if os.path.exists(MASTER_HASH_FILE):
        os.remove(MASTER_HASH_FILE)
