"""
db_manager.py — Database Module for Password Manager

Manages all SQLite CRUD operations for the credentials vault.
Each function opens its own connection, performs the operation, commits,
and closes — no persistent connection is kept open (matches Week 3 design).

Security notes:
- All queries use parameterised placeholders (?) to prevent SQL injection.
- The encrypted_pass column is BLOB to store raw Fernet token bytes.
- No plaintext passwords are ever written to the database.
"""

import os
import sqlite3
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────────────────────

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "vault.db")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_connection() -> sqlite3.Connection:
    """
    Open a new SQLite connection to the vault database.
    Creates the data directory if it does not exist.

    Returns:
        sqlite3.Connection: An open database connection.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")  # better concurrency
    return conn


# ── Table Initialisation ──────────────────────────────────────────────────────

def init_db() -> None:
    """
    Create the credentials table if it does not already exist.

    Schema:
        id              INTEGER PRIMARY KEY AUTOINCREMENT
        website         TEXT    NOT NULL
        username        TEXT    NOT NULL
        encrypted_pass  BLOB   NOT NULL
        notes           TEXT    DEFAULT ''
        created_at      TEXT    (ISO-8601 timestamp)
        updated_at      TEXT    (ISO-8601 timestamp)
    """
    conn = _get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                website         TEXT    NOT NULL,
                username        TEXT    NOT NULL,
                encrypted_pass  BLOB   NOT NULL,
                notes           TEXT    DEFAULT '',
                created_at      TEXT    DEFAULT (datetime('now', 'localtime')),
                updated_at      TEXT    DEFAULT (datetime('now', 'localtime'))
            );
        """)
        conn.commit()
    finally:
        conn.close()


# ── CRUD Operations ───────────────────────────────────────────────────────────

def insert_credential(website: str, username: str,
                      encrypted_pass: bytes, notes: str = "") -> int:
    """
    Insert a new credential into the vault.

    Args:
        website: Website or application name.
        username: Account username or email.
        encrypted_pass: Fernet-encrypted password (bytes).
        notes: Optional notes about this credential.

    Returns:
        int: The row ID of the newly inserted credential.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = _get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO credentials
               (website, username, encrypted_pass, notes, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (website, username, encrypted_pass, notes, now, now),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_all_credentials() -> list:
    """
    Retrieve all credentials from the vault.

    Returns:
        list[tuple]: Each tuple is
            (id, website, username, encrypted_pass, notes, created_at, updated_at).
    """
    conn = _get_connection()
    try:
        cursor = conn.execute(
            "SELECT id, website, username, encrypted_pass, notes, "
            "created_at, updated_at FROM credentials ORDER BY website ASC"
        )
        return cursor.fetchall()
    finally:
        conn.close()


def get_credential_by_id(cred_id: int) -> tuple | None:
    """
    Retrieve a single credential by its primary key.

    Args:
        cred_id: The credential row ID.

    Returns:
        tuple or None: The credential row, or None if not found.
    """
    conn = _get_connection()
    try:
        cursor = conn.execute(
            "SELECT id, website, username, encrypted_pass, notes, "
            "created_at, updated_at FROM credentials WHERE id = ?",
            (cred_id,),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def update_credential(cred_id: int, website: str, username: str,
                      encrypted_pass: bytes, notes: str = "") -> bool:
    """
    Update an existing credential.

    Args:
        cred_id: The credential row ID to update.
        website: Updated website/app name.
        username: Updated username.
        encrypted_pass: Updated Fernet-encrypted password.
        notes: Updated notes.

    Returns:
        bool: True if a row was updated, False if the ID was not found.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = _get_connection()
    try:
        cursor = conn.execute(
            """UPDATE credentials
               SET website = ?, username = ?, encrypted_pass = ?,
                   notes = ?, updated_at = ?
               WHERE id = ?""",
            (website, username, encrypted_pass, notes, now, cred_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def delete_credential(cred_id: int) -> bool:
    """
    Delete a credential by its primary key.

    Args:
        cred_id: The credential row ID to delete.

    Returns:
        bool: True if a row was deleted, False if the ID was not found.
    """
    conn = _get_connection()
    try:
        cursor = conn.execute(
            "DELETE FROM credentials WHERE id = ?",
            (cred_id,),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def search_credentials(query: str) -> list:
    """
    Search credentials by website or username (case-insensitive LIKE).

    Args:
        query: The search string to match against website and username.

    Returns:
        list[tuple]: Matching credential rows.
    """
    conn = _get_connection()
    try:
        pattern = f"%{query}%"
        cursor = conn.execute(
            "SELECT id, website, username, encrypted_pass, notes, "
            "created_at, updated_at FROM credentials "
            "WHERE website LIKE ? OR username LIKE ? "
            "ORDER BY website ASC",
            (pattern, pattern),
        )
        return cursor.fetchall()
    finally:
        conn.close()
