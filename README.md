# LockBox

Your personal digital safe. Protect photos, documents, videos — anything private — with a password. Just lock your files and only you can open them.

## Requirements

- Python 3.10+
- `cryptography` library (installed automatically by `encrypt.sh`)

## Quick Start

```bash
# Make the script executable (first time only)
chmod +x encrypt.sh

# Encrypt a file
./encrypt.sh encrypt secret.pdf

# Encrypt a directory
./encrypt.sh encrypt ~/Documents/private

# Decrypt
./encrypt.sh decrypt secret_encrypted/
```

## What Happens When You Encrypt

**Single file** (`./encrypt.sh encrypt photo.jpg`):
```
photo_encrypted/   ← encrypted file with a fake system-like name
photo_archival/    ← original file moved here
```

**Directory** (`./encrypt.sh encrypt documents`):
```
documents_encrypted/   ← mirrors original structure, fake filenames
documents_archival/    ← originals moved here, structure preserved
```

The original filename is stored **inside** the encrypted payload — the fake name on disk reveals nothing.

## What Happens When You Decrypt

```bash
./encrypt.sh decrypt <encrypted_file_or_dir> [output_dir]
```

The original filename is recovered from inside the payload and the file is restored. If no `output_dir` is given, the file is restored in the same directory.

## Security

| Layer | Algorithm | Standard |
|-------|-----------|----------|
| Cipher | AES-256-GCM | NIST SP 800-38D |
| Key derivation | PBKDF2-HMAC-SHA256 (600,000 iterations) | RFC 2898 / NIST SP 800-132 |
| Salt | 32 bytes random per file | — |
| Nonce | 12 bytes random base, incremented per chunk | NIST GCM recommendation |

- Password is **never stored** — entered at runtime via secure prompt, used to derive the AES key, then discarded
- Each file gets a unique random salt → same password produces a different key per file
- GCM authentication tag detects any tampering or corruption

## Long-term Recovery

Even if this script or its dependencies are unavailable in the future, files can be decrypted using any standard AES-256-GCM + PBKDF2-SHA256 implementation. The full file format spec and a minimal standalone re-implementation are documented inside `encrypt.py`.

The algorithms used are RFC-standardized and implemented in every major language and cryptography library.

## File Format (brief)

```
[4 bytes]  Magic: "ENCF"
[32 bytes] Salt (plaintext)
[12 bytes] Base nonce (plaintext)
[4 bytes]  Chunk length
[N bytes]  Encrypted chunk 0: original filename
[4 bytes]  Chunk length
[N bytes]  Encrypted chunk 1: file data (up to 64 KB)
           ... repeated until EOF
```

See `encrypt.py` module docstring for the full byte-level specification.

## Files

```
encrypt.sh        — run this to encrypt/decrypt (sets up venv automatically)
encrypt.py        — core script (also documents full re-engineering spec)
requirements.txt  — Python dependencies
.venv/            — created automatically on first run, safe to delete and recreate
```
