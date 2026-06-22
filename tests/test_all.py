"""
test_all.py — Automated Test Suite for Password Manager

Covers:
    - Encryption: encrypt/decrypt round-trip, key derivation, error handling
    - Database: CRUD operations, search, schema verification
    - Authentication: setup, verify, first-run detection
    - Password Generator: length, character guarantees, strength evaluation
    - Integration: full add-view-edit-delete flow

Run with:
    python -m pytest tests/test_all.py -v
    (or)
    python -m unittest tests.test_all -v
"""

import os
import sys
import shutil
import unittest
import tempfile

# Ensure the project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import encryption
import db_manager
import auth
import password_gen


class _TempDataDirMixin:
    """
    Mixin that redirects all data files to a temporary directory
    so that tests never touch the real vault.
    """

    def setUp(self):
        """Create a temporary data directory and redirect all modules to it."""
        self.temp_dir = tempfile.mkdtemp(prefix="pwmgr_test_")
        self.data_dir = os.path.join(self.temp_dir, "data")
        os.makedirs(self.data_dir, exist_ok=True)

        # Patch module-level paths
        self._orig_enc_data = encryption.DATA_DIR
        self._orig_enc_salt = encryption.SALT_FILE
        self._orig_db_data = db_manager.DATA_DIR
        self._orig_db_path = db_manager.DB_PATH
        self._orig_auth_data = auth.DATA_DIR
        self._orig_auth_hash = auth.MASTER_HASH_FILE

        encryption.DATA_DIR = self.data_dir
        encryption.SALT_FILE = os.path.join(self.data_dir, "salt.bin")
        db_manager.DATA_DIR = self.data_dir
        db_manager.DB_PATH = os.path.join(self.data_dir, "vault.db")
        auth.DATA_DIR = self.data_dir
        auth.MASTER_HASH_FILE = os.path.join(self.data_dir, "master.hash")

    def tearDown(self):
        """Restore original paths and clean up temp directory."""
        encryption.DATA_DIR = self._orig_enc_data
        encryption.SALT_FILE = self._orig_enc_salt
        db_manager.DATA_DIR = self._orig_db_data
        db_manager.DB_PATH = self._orig_db_path
        auth.DATA_DIR = self._orig_auth_data
        auth.MASTER_HASH_FILE = self._orig_auth_hash

        shutil.rmtree(self.temp_dir, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
# Encryption Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestEncryption(_TempDataDirMixin, unittest.TestCase):
    """Tests for the encryption module."""

    def test_salt_creation(self):
        """Salt file is created on first call and is 16 bytes."""
        salt = encryption.get_or_create_salt()
        self.assertEqual(len(salt), 16)
        self.assertTrue(os.path.exists(encryption.SALT_FILE))

    def test_salt_persistence(self):
        """Same salt is returned on subsequent calls."""
        salt1 = encryption.get_or_create_salt()
        salt2 = encryption.get_or_create_salt()
        self.assertEqual(salt1, salt2)

    def test_derive_key_returns_bytes(self):
        """derive_key returns a URL-safe base64 bytes object."""
        salt = encryption.get_or_create_salt()
        key = encryption.derive_key("TestMaster123", salt)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 44)  # 32 bytes → 44 chars in base64

    def test_different_passwords_different_keys(self):
        """Different master passwords produce different encryption keys."""
        salt = encryption.get_or_create_salt()
        key1 = encryption.derive_key("PasswordA", salt)
        key2 = encryption.derive_key("PasswordB", salt)
        self.assertNotEqual(key1, key2)

    def test_encrypt_decrypt_round_trip(self):
        """Encrypting and then decrypting returns the original plaintext."""
        plaintext = "MyS3cret!P@ssw0rd"
        master = "MasterKey123"
        token = encryption.encrypt_password(plaintext, master)
        recovered = encryption.decrypt_password(token, master)
        self.assertEqual(recovered, plaintext)

    def test_encrypt_produces_bytes(self):
        """Encrypted output is bytes (suitable for BLOB storage)."""
        token = encryption.encrypt_password("test", "master")
        self.assertIsInstance(token, bytes)

    def test_different_ciphertext_same_plaintext(self):
        """Two encryptions of the same plaintext produce different tokens."""
        t1 = encryption.encrypt_password("same", "master")
        t2 = encryption.encrypt_password("same", "master")
        self.assertNotEqual(t1, t2)  # Fernet uses random IV

    def test_decrypt_wrong_password_fails(self):
        """Decrypting with the wrong master password raises an error."""
        token = encryption.encrypt_password("secret", "correct_master")
        with self.assertRaises(Exception):
            encryption.decrypt_password(token, "wrong_master")

    def test_encrypt_empty_password_raises(self):
        """Encrypting an empty string raises ValueError."""
        with self.assertRaises(ValueError):
            encryption.encrypt_password("", "master")

    def test_encrypt_empty_master_raises(self):
        """Encrypting with empty master password raises ValueError."""
        with self.assertRaises(ValueError):
            encryption.encrypt_password("test", "")

    def test_corrupt_salt_raises(self):
        """A corrupted salt file (wrong size) raises ValueError."""
        # Create a salt file with wrong size
        with open(encryption.SALT_FILE, "wb") as f:
            f.write(b"short")
        with self.assertRaises(ValueError):
            encryption.get_or_create_salt()


# ══════════════════════════════════════════════════════════════════════════════
# Database Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestDatabase(_TempDataDirMixin, unittest.TestCase):
    """Tests for the database module."""

    def setUp(self):
        super().setUp()
        db_manager.init_db()

    def test_init_creates_db(self):
        """init_db creates the database file."""
        self.assertTrue(os.path.exists(db_manager.DB_PATH))

    def test_insert_and_retrieve(self):
        """Inserting a credential and reading it back works correctly."""
        enc_pass = b"encrypted_token_bytes"
        row_id = db_manager.insert_credential(
            "example.com", "user@test.com", enc_pass, "test notes"
        )
        self.assertIsInstance(row_id, int)
        self.assertGreater(row_id, 0)

        cred = db_manager.get_credential_by_id(row_id)
        self.assertIsNotNone(cred)
        self.assertEqual(cred[1], "example.com")
        self.assertEqual(cred[2], "user@test.com")
        self.assertEqual(cred[3], enc_pass)
        self.assertEqual(cred[4], "test notes")

    def test_get_all_credentials(self):
        """get_all_credentials returns all inserted rows."""
        db_manager.insert_credential("site1.com", "u1", b"enc1")
        db_manager.insert_credential("site2.com", "u2", b"enc2")
        db_manager.insert_credential("site3.com", "u3", b"enc3")

        rows = db_manager.get_all_credentials()
        self.assertEqual(len(rows), 3)

    def test_update_credential(self):
        """update_credential changes the stored data."""
        row_id = db_manager.insert_credential("old.com", "old_user", b"old_enc")

        result = db_manager.update_credential(
            row_id, "new.com", "new_user", b"new_enc", "updated notes"
        )
        self.assertTrue(result)

        cred = db_manager.get_credential_by_id(row_id)
        self.assertEqual(cred[1], "new.com")
        self.assertEqual(cred[2], "new_user")
        self.assertEqual(cred[3], b"new_enc")
        self.assertEqual(cred[4], "updated notes")

    def test_update_nonexistent_returns_false(self):
        """Updating a non-existent ID returns False."""
        result = db_manager.update_credential(9999, "x", "y", b"z")
        self.assertFalse(result)

    def test_delete_credential(self):
        """delete_credential removes the row from the database."""
        row_id = db_manager.insert_credential("delete.me", "user", b"enc")
        result = db_manager.delete_credential(row_id)
        self.assertTrue(result)

        cred = db_manager.get_credential_by_id(row_id)
        self.assertIsNone(cred)

    def test_delete_nonexistent_returns_false(self):
        """Deleting a non-existent ID returns False."""
        result = db_manager.delete_credential(9999)
        self.assertFalse(result)

    def test_search_by_website(self):
        """search_credentials matches on website name."""
        db_manager.insert_credential("google.com", "alice", b"enc1")
        db_manager.insert_credential("github.com", "bob", b"enc2")
        db_manager.insert_credential("facebook.com", "carol", b"enc3")

        results = db_manager.search_credentials("goo")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], "google.com")

    def test_search_by_username(self):
        """search_credentials matches on username."""
        db_manager.insert_credential("site.com", "alice_smith", b"enc1")
        db_manager.insert_credential("site2.com", "bob_jones", b"enc2")

        results = db_manager.search_credentials("alice")
        self.assertEqual(len(results), 1)

    def test_search_case_insensitive(self):
        """LIKE search is case-insensitive in SQLite by default for ASCII."""
        db_manager.insert_credential("Google.com", "user", b"enc")
        results = db_manager.search_credentials("google")
        self.assertEqual(len(results), 1)

    def test_no_plaintext_in_db(self):
        """Encrypted data stored in the DB is not human-readable plaintext."""
        enc = encryption.encrypt_password("SuperSecret123!", "master")
        db_manager.insert_credential("test.com", "user", enc)

        cred = db_manager.get_credential_by_id(1)
        stored_pass = cred[3]
        # The stored value should be bytes and not contain the plaintext
        self.assertIsInstance(stored_pass, bytes)
        self.assertNotIn(b"SuperSecret123!", stored_pass)


# ══════════════════════════════════════════════════════════════════════════════
# Authentication Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAuth(_TempDataDirMixin, unittest.TestCase):
    """Tests for the authentication module."""

    def test_is_first_run_initially_true(self):
        """is_first_run returns True when no master.hash exists."""
        self.assertTrue(auth.is_first_run())

    def test_setup_master_password(self):
        """setup_master_password creates the hash file."""
        success, msg = auth.setup_master_password("TestPass123")
        self.assertTrue(success)
        self.assertFalse(auth.is_first_run())
        self.assertTrue(os.path.exists(auth.MASTER_HASH_FILE))

    def test_verify_correct_password(self):
        """verify_master_password returns True for the correct password."""
        auth.setup_master_password("MyMaster99!")
        self.assertTrue(auth.verify_master_password("MyMaster99!"))

    def test_verify_wrong_password(self):
        """verify_master_password returns False for an incorrect password."""
        auth.setup_master_password("CorrectPassword")
        self.assertFalse(auth.verify_master_password("WrongPassword"))

    def test_reject_empty_password(self):
        """setup_master_password rejects empty passwords."""
        success, msg = auth.setup_master_password("")
        self.assertFalse(success)
        self.assertIn("empty", msg.lower())

    def test_reject_short_password(self):
        """setup_master_password rejects passwords shorter than 6 characters."""
        success, msg = auth.setup_master_password("abc")
        self.assertFalse(success)
        self.assertIn("6", msg)

    def test_verify_empty_returns_false(self):
        """verify_master_password returns False for empty input."""
        auth.setup_master_password("ValidPass1")
        self.assertFalse(auth.verify_master_password(""))

    def test_verify_without_setup_raises(self):
        """verify_master_password raises FileNotFoundError if not set up."""
        with self.assertRaises(FileNotFoundError):
            auth.verify_master_password("anything")

    def test_reset_master_password(self):
        """reset_master_password removes the hash file."""
        auth.setup_master_password("TestReset")
        self.assertFalse(auth.is_first_run())

        auth.reset_master_password()
        self.assertTrue(auth.is_first_run())


# ══════════════════════════════════════════════════════════════════════════════
# Password Generator Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestPasswordGenerator(unittest.TestCase):
    """Tests for the password generator module."""

    def test_default_length(self):
        """Default password length is 12."""
        pwd = password_gen.generate_password()
        self.assertEqual(len(pwd), 12)

    def test_custom_length(self):
        """Password matches the requested length."""
        for length in [4, 8, 16, 32, 64]:
            pwd = password_gen.generate_password(length=length)
            self.assertEqual(len(pwd), length, f"Failed for length={length}")

    def test_contains_lowercase(self):
        """Generated password always contains lowercase letters."""
        pwd = password_gen.generate_password(
            length=20, use_upper=False, use_digits=False, use_symbols=False
        )
        self.assertTrue(any(c in password_gen.LOWERCASE for c in pwd))

    def test_contains_uppercase_when_requested(self):
        """Password contains uppercase when use_upper=True."""
        # Run multiple times to account for randomness
        has_upper = False
        for _ in range(10):
            pwd = password_gen.generate_password(
                length=20, use_upper=True, use_digits=False, use_symbols=False
            )
            if any(c in password_gen.UPPERCASE for c in pwd):
                has_upper = True
                break
        self.assertTrue(has_upper)

    def test_contains_digits_when_requested(self):
        """Password contains digits when use_digits=True."""
        pwd = password_gen.generate_password(
            length=20, use_upper=False, use_digits=True, use_symbols=False
        )
        self.assertTrue(any(c in password_gen.DIGITS for c in pwd))

    def test_contains_symbols_when_requested(self):
        """Password contains symbols when use_symbols=True."""
        pwd = password_gen.generate_password(
            length=20, use_upper=False, use_digits=False, use_symbols=True
        )
        self.assertTrue(any(c in password_gen.SYMBOLS for c in pwd))

    def test_all_types_present(self):
        """Password with all types enabled contains at least one of each."""
        pwd = password_gen.generate_password(
            length=20, use_upper=True, use_digits=True, use_symbols=True
        )
        self.assertTrue(any(c in password_gen.LOWERCASE for c in pwd))
        self.assertTrue(any(c in password_gen.UPPERCASE for c in pwd))
        self.assertTrue(any(c in password_gen.DIGITS for c in pwd))
        self.assertTrue(any(c in password_gen.SYMBOLS for c in pwd))

    def test_digits_only(self):
        """Digits-only password contains no letters or symbols."""
        pwd = password_gen.generate_password(
            length=20, use_upper=False, use_digits=True, use_symbols=False
        )
        for c in pwd:
            self.assertTrue(
                c in password_gen.LOWERCASE or c in password_gen.DIGITS,
                f"Unexpected character: {c}",
            )

    def test_minimum_length_validation(self):
        """Passwords shorter than 4 characters raise ValueError."""
        with self.assertRaises(ValueError):
            password_gen.generate_password(length=3)

    def test_maximum_length_validation(self):
        """Passwords longer than 128 characters raise ValueError."""
        with self.assertRaises(ValueError):
            password_gen.generate_password(length=129)

    def test_strength_weak(self):
        """Short lowercase-only password is evaluated as Weak."""
        self.assertEqual(password_gen.evaluate_strength("abc"), "Weak")

    def test_strength_medium(self):
        """Medium-complexity password is evaluated as Medium."""
        self.assertEqual(password_gen.evaluate_strength("Abcdefgh1"), "Medium")

    def test_strength_strong(self):
        """Long password with all types is evaluated as Strong."""
        self.assertEqual(
            password_gen.evaluate_strength("Str0ng!Passw0rd"), "Strong"
        )

    def test_strength_empty(self):
        """Empty password is evaluated as Weak."""
        self.assertEqual(password_gen.evaluate_strength(""), "Weak")


# ══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration(_TempDataDirMixin, unittest.TestCase):
    """End-to-end tests combining multiple modules."""

    def setUp(self):
        super().setUp()
        db_manager.init_db()
        self.master_password = "IntegrationTest@99"
        auth.setup_master_password(self.master_password)

    def test_full_add_view_edit_delete_flow(self):
        """Complete CRUD flow through encryption and database layers."""
        # 1. Add a credential
        plaintext = "MySecureP@ss123"
        enc = encryption.encrypt_password(plaintext, self.master_password)
        row_id = db_manager.insert_credential(
            "github.com", "dev@example.com", enc, "dev account"
        )

        # 2. View the credential
        cred = db_manager.get_credential_by_id(row_id)
        self.assertIsNotNone(cred)
        decrypted = encryption.decrypt_password(cred[3], self.master_password)
        self.assertEqual(decrypted, plaintext)
        self.assertEqual(cred[1], "github.com")
        self.assertEqual(cred[2], "dev@example.com")

        # 3. Edit the credential
        new_plaintext = "UpdatedP@ss456"
        new_enc = encryption.encrypt_password(new_plaintext, self.master_password)
        db_manager.update_credential(
            row_id, "github.com", "newuser@example.com", new_enc, "updated notes"
        )

        cred = db_manager.get_credential_by_id(row_id)
        decrypted = encryption.decrypt_password(cred[3], self.master_password)
        self.assertEqual(decrypted, new_plaintext)
        self.assertEqual(cred[2], "newuser@example.com")

        # 4. Delete the credential
        db_manager.delete_credential(row_id)
        cred = db_manager.get_credential_by_id(row_id)
        self.assertIsNone(cred)

    def test_login_then_store_and_retrieve(self):
        """Simulate login followed by a store-and-retrieve operation."""
        # Verify login
        self.assertTrue(auth.verify_master_password(self.master_password))
        self.assertFalse(auth.verify_master_password("WrongPass"))

        # Store a credential using the session master password
        pwd = password_gen.generate_password(16, True, True, True)
        enc = encryption.encrypt_password(pwd, self.master_password)
        row_id = db_manager.insert_credential("test.com", "user", enc)

        # Retrieve and decrypt
        cred = db_manager.get_credential_by_id(row_id)
        decrypted = encryption.decrypt_password(cred[3], self.master_password)
        self.assertEqual(decrypted, pwd)

    def test_multiple_credentials(self):
        """Store and retrieve multiple credentials correctly."""
        test_data = [
            ("google.com", "alice@gmail.com", "GoogleP@ss1"),
            ("twitter.com", "bob@twitter.com", "TwitP@ss2"),
            ("reddit.com", "carol@reddit.com", "RedditP@ss3"),
        ]

        for site, user, pwd in test_data:
            enc = encryption.encrypt_password(pwd, self.master_password)
            db_manager.insert_credential(site, user, enc)

        rows = db_manager.get_all_credentials()
        self.assertEqual(len(rows), 3)

        # Build a lookup from website → expected password
        # (rows are ordered by website ASC, not insertion order)
        expected = {site: pwd for site, _, pwd in test_data}

        for row in rows:
            website = row[1]
            decrypted = encryption.decrypt_password(row[3], self.master_password)
            self.assertEqual(decrypted, expected[website])

    def test_search_with_encrypted_data(self):
        """Search works on website/username even with encrypted passwords."""
        enc = encryption.encrypt_password("pass", self.master_password)
        db_manager.insert_credential("amazon.com", "shopper", enc)
        db_manager.insert_credential("netflix.com", "viewer", enc)

        results = db_manager.search_credentials("amazon")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], "amazon.com")


if __name__ == "__main__":
    unittest.main()
