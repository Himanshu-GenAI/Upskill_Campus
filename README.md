## Internship Submission

This repository contains:

- Final project source code
- Final internship report (PDF & DOCX)
- Complete Password Manager desktop application developed using Python
  
# 🔐 Password Manager

A secure desktop password manager built with Python, Tkinter, SQLite, and Fernet encryption.

> **Student Project** — Himanshu Rautela, B.Tech CSE (AI/ML), GLA University

---

## Features

- **Master Password Authentication** — PBKDF2-HMAC-SHA256 key derivation with salted SHA-256 hash verification
- **Fernet Encryption** — All stored passwords are encrypted using AES-128-CBC + HMAC-SHA256 (via Fernet)
- **Full CRUD Operations** — Add, view, edit, and delete credentials
- **Search** — Filter credentials by website or username
- **Password Generator** — Configurable length (4–64 chars) with uppercase, digits, and symbols options
- **Password Strength Indicator** — Weak / Medium / Strong evaluation
- **Dark-Themed GUI** — Modern dark interface built with Tkinter + ttk
- **No Plaintext Storage** — Passwords are never stored in plaintext anywhere on disk
- **Logout Support** — Session key cleared from memory on logout

---

## Project Structure

```
password_manager/
├── main.py              # Entry point — run this to start the app
├── gui.py               # Tkinter GUI (all screens)
├── auth.py              # Master password setup & verification
├── encryption.py        # PBKDF2 key derivation + Fernet encrypt/decrypt
├── db_manager.py        # SQLite CRUD operations
├── password_gen.py      # Secure password generator
├── requirements.txt     # Python dependencies
├── README.md            # This file
├── data/                # Runtime data (auto-created)
│   ├── vault.db         # SQLite database with encrypted credentials
│   ├── salt.bin         # 16-byte encryption salt
│   └── master.hash      # SHA-256 hash of the master password
└── tests/
    ├── __init__.py
    └── test_all.py      # Automated test suite (49 tests)
```

---

## Requirements

- Python 3.11 or higher
- `cryptography` library

---

## Installation

1. **Clone or download** this project.

2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### Run the Application

```bash
python main.py
```

### First Run

1. The app will display a **Setup Screen** — create your master password (minimum 6 characters).
2. After setup, you will be taken to the **Login Screen**.

### Login

1. Enter your master password.
2. The dashboard will open showing your saved credentials.

### Dashboard Operations

| Action | Description |
|--------|-------------|
| **➕ Add Password** | Opens a form to save a new credential (website, username, password, notes) |
| **✏️ Edit** | Opens the selected credential for editing |
| **🗑️ Delete** | Deletes the selected credential (with confirmation) |
| **🎲 Generator** | Opens the password generator tool |
| **🔍 Search** | Type in the search bar to filter credentials |
| **🚪 Logout** | Clears session and returns to login screen |

---

## Running Tests

```bash
python -m pytest tests/test_all.py -v
```

All 49 tests cover:

| Category | Tests | Scope |
|----------|-------|-------|
| Encryption | 11 | Salt management, key derivation, encrypt/decrypt, error handling |
| Database | 10 | CRUD operations, search, no-plaintext verification |
| Authentication | 9 | Setup, verify, first-run, validation, reset |
| Password Generator | 14 | Length, character types, strength evaluation |
| Integration | 4 | End-to-end CRUD flow, login + store/retrieve |

---

## Security Architecture

| Component | Implementation |
|-----------|---------------|
| Master password | SHA-256(password + salt) → stored as hex digest |
| Encryption key | PBKDF2-HMAC-SHA256, 200,000 iterations → Fernet key |
| Password storage | Fernet token (bytes) → BLOB column in SQLite |
| Salt | 16-byte `os.urandom()` → `data/salt.bin` |
| Key persistence | Never stored on disk; derived at login, held in memory only |
| SQL injection | Parameterised queries (?) throughout |
| Session end | Key cleared from memory on logout / app close |

---

## Technology Stack

| Technology | Purpose |
|------------|---------|
| Python 3.x | Application logic |
| Tkinter + ttk | Desktop GUI |
| SQLite 3 | Local database (vault.db) |
| cryptography (Fernet) | Symmetric encryption |
| hashlib (SHA-256, PBKDF2) | Hashing and key derivation |
| secrets + string | Cryptographically secure password generation |

---

## Future Improvements

- Password strength meter in real-time while typing
- Encrypted vault backup / export / import
- Auto-lock after inactivity timeout
- Clipboard auto-clear after a few seconds
- Category/tag support for credentials
- Theming library for improved GUI aesthetics

---

## License

This is a student internship project. Use at your own risk.
