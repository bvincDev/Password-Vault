# Password-Vault

A small, lightweight password vault/demo app written in Python.

It uses a master password (SHA-256 hash) and encrypts stored credentials with
Fernet (from the `cryptography` package). This repository is intended for
learning and experimentation — do not use it in production without a security
review and hardening.

## What it does

- On first run, prompts you to create a master password.
- Login screen enforces up to 3 incorrect attempts before the app exits.
- Add, edit, delete, and search saved credentials.
- Credentials are encrypted with Fernet; the encryption key is stored in the
  local SQLite database alongside the hashed master password (see security
  notes below).

## Files

- `vault.py` — main application (Tkinter GUI, DB operations, encryption helpers)
- `vault.db` — SQLite database that is created automatically by the app

## Requirements

- Python 3.8+
- cryptography


```To get cryptography library
pip install cryptography
```

## Running

Start the app with:

```powershell
python vault.py
```

The GUI will guide you through creating a master password and managing entries.

## Security notes (important)

- The master password is hashed with SHA-256. A stronger scheme using a KDF
  (PBKDF2/Argon2) with a salt is recommended.
- This app stores data locally in `vault.db`. If an attacker gains access to
  the file system, the database (and stored key) can be compromised.

This project is educational;

## future improvements

- Derive the encryption key from the master password using a proper KDF.
- Use per-user salt and a memory-hard KDF (Argon2) for master password hashing.
- Protect the encryption key using the OS keyring or HSM when available.
- Add an encrypted export/import backup feature.
