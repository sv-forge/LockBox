#!/usr/bin/env python3
"""
Encrypt / decrypt files or directories using AES-256-GCM.
Encrypted files are saved with random system-like names; the original
filename is stored inside the encrypted payload and restored on decryption.

Encrypt behaviour:
  Single file  → <parent>/<stem>_encrypted/<fake-name>
                 original moved to <parent>/<stem>_archival/<original-name>
  Directory    → <dir>_encrypted/ (mirrors structure, fake names)
                 originals moved to <dir>_archival/ (mirrors structure)

Usage:
  python encrypt.py encrypt <file_or_dir>
  python encrypt.py decrypt <file_or_dir> [<output_dir>]

════════════════════════════════════════════════════════════════════════════════
RE-ENGINEERING REFERENCE — everything needed to decrypt files without this script
════════════════════════════════════════════════════════════════════════════════

CRYPTOGRAPHIC PRIMITIVES
────────────────────────
  KDF  : PBKDF2-HMAC-SHA256
           iterations : 600,000  (OWASP 2023 recommendation)
           salt length: 32 bytes (per-file, stored in plaintext in the file)
           key length : 32 bytes → used as AES-256 key
           password   : UTF-8 encoded before passing to PBKDF2

  Cipher: AES-256-GCM (authenticated encryption)
           nonce length: 12 bytes (96-bit, NIST recommended for GCM)
           tag length  : 16 bytes (GCM default, appended to ciphertext by the library)
           AAD         : None (no additional authenticated data used)

  Nonce management: a random 12-byte base nonce is stored in the file header.
    It is interpreted as a big-endian integer and incremented by 1 for each
    successive chunk. This guarantees nonce uniqueness per (key, chunk) pair
    without storing per-chunk nonces on disk.

BINARY FILE FORMAT
──────────────────
  All multi-byte integers are big-endian.

  Offset  Size  Description
  ──────  ────  ───────────────────────────────────────────────────────────────
       0     4  Magic bytes: ASCII "ENCF"  (0x45 0x4E 0x43 0x46)
       4    32  Salt (random, used with password to derive AES key via PBKDF2)
      36    12  Base nonce (random; incremented per chunk — see Nonce management)
      48     4  Length of chunk-0 ciphertext (uint32 big-endian)
      52     N  Chunk-0 ciphertext (plaintext = 2-byte name-len + name bytes)
    52+N     4  Length of chunk-1 ciphertext (uint32 big-endian)
    56+N     M  Chunk-1 ciphertext (plaintext = up to 64 KB of file data)
               ... repeated until EOF ...

  Chunk-0 (filename chunk) plaintext layout:
    Bytes 0-1 : uint16 big-endian — byte length of the original filename
    Bytes 2-N : original filename encoded as UTF-8

  Each chunk's ciphertext includes the 16-byte GCM authentication tag
  appended by the library, so:
    len(ciphertext) = len(plaintext) + 16

STEP-BY-STEP DECRYPTION (language-agnostic)
────────────────────────────────────────────
  1. Open the file in binary mode.
  2. Read and verify bytes 0-3 == b"ENCF". Abort if not.
  3. Read bytes 4-35  → salt      (32 bytes)
  4. Read bytes 36-47 → base_nonce (12 bytes)
  5. Derive key:
       key = PBKDF2_HMAC_SHA256(password_utf8, salt, iterations=600_000, dklen=32)
  6. nonce_int = big-endian integer of base_nonce
  7. Loop (chunk 0, 1, 2, …):
       a. Read 4 bytes → ct_len (uint32 big-endian). If EOF, stop.
       b. Read ct_len bytes → ciphertext (includes 16-byte GCM tag at end).
       c. chunk_nonce = nonce_int encoded as 12-byte big-endian integer
       d. plaintext = AES_256_GCM_decrypt(key, chunk_nonce, ciphertext, aad=None)
          — if authentication fails, the password is wrong or the file is corrupt.
       e. nonce_int += 1
       f. If this is chunk 0:
            name_len = uint16 big-endian from plaintext[0:2]
            original_filename = plaintext[2 : 2+name_len].decode("utf-8")
          Else: write plaintext bytes to the output file.
  8. The output file is now fully restored with its original filename.

RECOVERY WITHOUT THIS SCRIPT
─────────────────────────────
  The algorithm uses only standard, RFC-specified primitives:
    • PBKDF2  — RFC 2898 / NIST SP 800-132
    • AES-GCM — NIST SP 800-38D
  Any modern cryptography library in any language implements these.
  Libraries known to work: Python `cryptography`, OpenSSL, libsodium (via wrappers),
  Java javax.crypto, Go crypto/aes + crypto/cipher, Node.js crypto module.

  Minimal Python re-implementation (no dependencies except `cryptography`):

    import struct, hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    def decrypt(src_path, dst_dir, password):
        with open(src_path, "rb") as f:
            assert f.read(4) == b"ENCF", "not an ENCF file"
            salt  = f.read(32)
            nonce = f.read(12)
            kdf   = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000)
            key   = kdf.derive(password.encode())
            gcm   = AESGCM(key)
            n     = int.from_bytes(nonce, "big")
            name  = None
            out   = None
            while chunk_len_bytes := f.read(4):
                ct  = f.read(struct.unpack(">I", chunk_len_bytes)[0])
                pt  = gcm.decrypt(n.to_bytes(12, "big"), ct, None)
                n  += 1
                if name is None:
                    name_len = struct.unpack(">H", pt[:2])[0]
                    name = pt[2:2+name_len].decode("utf-8")
                    out  = open(dst_dir + "/" + name, "wb")
                else:
                    out.write(pt)
            if out: out.close()

════════════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import struct
import getpass
import secrets
import string
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ── constants ──────────────────────────────────────────────────────────────────

SALT_LEN  = 32        # bytes — random per file, stored plaintext in header
NONCE_LEN = 12        # bytes — 96-bit base nonce, incremented per chunk
KDF_ITERS = 600_000   # OWASP 2023 recommendation for PBKDF2-SHA256
CHUNK     = 64 * 1024 # 64 KB — keeps RAM flat for large files

MAGIC = b"ENCF"  # first 4 bytes of every encrypted file; used to detect format

# Characters and extensions used to generate plausible-looking system filenames,
# obscuring the fact that the file is an encrypted payload.
_FAKE_CHARS = string.ascii_lowercase + string.digits
_FAKE_EXTS = [
    ".dat", ".tmp", ".log", ".sys", ".bin",
    ".bak", ".cache", ".db",  ".idx", ".cfg",
]


# ── fake filename generator ────────────────────────────────────────────────────

def _random_fake_name() -> str:
    """Return a name like  mq7x_k2p9rf.dat  that looks like a system temp file."""
    prefix = "".join(secrets.choice(_FAKE_CHARS) for _ in range(4))
    suffix = "".join(secrets.choice(_FAKE_CHARS) for _ in range(6))
    ext    = secrets.choice(_FAKE_EXTS)
    return f"{prefix}_{suffix}{ext}"


def _unique_fake_name(directory: Path) -> str:
    """Generate a fake name that doesn't already exist in directory."""
    for _ in range(100):
        name = _random_fake_name()
        if not (directory / name).exists():
            return name
    raise RuntimeError("Could not generate a unique fake filename after 100 tries.")


# ── key derivation ─────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from password + salt using PBKDF2-HMAC-SHA256.

    The salt is random and stored plaintext in each encrypted file's header,
    so a different key is produced per file even when the same password is used.
    KDF_ITERS (600,000) is the OWASP 2023 minimum; increase it on future hardware
    if re-encrypting files, but update the constant consistently so decryption still works.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(password.encode())


# ── core encrypt / decrypt ─────────────────────────────────────────────────────

def _write_chunk(fout, aesgcm: AESGCM, nonce_int: int, data: bytes) -> int:
    """
    Encrypt data as one chunk and write [4-byte length][ciphertext] to fout.
    Returns the next nonce integer (caller must pass it to the next call).

    The nonce is derived from nonce_int encoded as a 12-byte big-endian integer.
    Incrementing it per chunk ensures nonce uniqueness for the same key without
    storing per-chunk nonces on disk.
    """
    chunk_nonce = nonce_int.to_bytes(NONCE_LEN, "big")
    ct = aesgcm.encrypt(chunk_nonce, data, None)  # ct includes 16-byte GCM tag
    fout.write(struct.pack(">I", len(ct)))
    fout.write(ct)
    return nonce_int + 1


def _read_chunk(fin, aesgcm: AESGCM, nonce_int: int, src: Path) -> tuple[bytes, int]:
    """
    Read one [4-byte length][ciphertext] chunk from fin, decrypt and return plaintext.
    Returns (b"", nonce_int) at EOF.
    Raises ValueError if GCM authentication fails (wrong password or corrupt file).
    """
    raw_len = fin.read(4)
    if not raw_len:
        return b"", nonce_int
    ct_len = struct.unpack(">I", raw_len)[0]
    ct = fin.read(ct_len)
    chunk_nonce = nonce_int.to_bytes(NONCE_LEN, "big")
    try:
        plaintext = aesgcm.decrypt(chunk_nonce, ct, None)
    except Exception:
        raise ValueError(f"{src}: decryption failed — wrong password or file is corrupted")
    return plaintext, nonce_int + 1


def _is_already_encrypted(path: Path) -> bool:
    """Return True if the file starts with the ENCF magic bytes."""
    with path.open("rb") as f:
        return f.read(4) == MAGIC


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    """
    Encrypt src → dst using AES-256-GCM.

    Header written to dst (all plaintext):
      [4]  magic "ENCF"
      [32] random salt
      [12] random base nonce

    Then chunks:
      Chunk 0: 2-byte name-len + original filename bytes  (encrypted)
      Chunk 1…N: 64 KB blocks of file content             (encrypted)

    The original filename is stored inside the payload so decryption can
    restore it regardless of the fake name used on disk.
    """
    if _is_already_encrypted(src):
        raise ValueError(f"{src}: already encrypted (skipping to avoid double-encryption)")

    salt  = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key   = derive_key(password, salt)
    aesgcm = AESGCM(key)

    src_size  = src.stat().st_size
    done      = 0
    nonce_int = int.from_bytes(nonce, "big")

    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(nonce)

        # Chunk 0: original filename encoded as uint16 length + UTF-8 bytes
        name_bytes = src.name.encode()
        nonce_int = _write_chunk(fout, aesgcm, nonce_int,
                                 struct.pack(">H", len(name_bytes)) + name_bytes)

        # Remaining chunks: raw file content in 64 KB blocks
        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            nonce_int = _write_chunk(fout, aesgcm, nonce_int, chunk)
            done += len(chunk)
            _progress(done, src_size)

    print()


def decrypt_file(src: Path, out_dir: Path, password: str) -> Path:
    """
    Decrypt src into out_dir, restoring the original filename from the payload.
    Returns the path of the restored file.
    Raises ValueError on bad magic bytes, wrong password, or corruption.
    """
    with src.open("rb") as fin:
        magic = fin.read(4)
        if magic != MAGIC:
            raise ValueError(f"{src}: not an encrypted file (bad magic bytes)")

        salt  = fin.read(SALT_LEN)
        nonce = fin.read(NONCE_LEN)
        key   = derive_key(password, salt)
        aesgcm = AESGCM(key)

        src_size  = src.stat().st_size
        done      = 4 + SALT_LEN + NONCE_LEN
        nonce_int = int.from_bytes(nonce, "big")

        # Chunk 0: recover original filename
        name_chunk, nonce_int = _read_chunk(fin, aesgcm, nonce_int, src)
        name_len  = struct.unpack(">H", name_chunk[:2])[0]
        raw_name  = name_chunk[2 : 2 + name_len]
        try:
            orig_name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            orig_name = raw_name.decode("latin-1")

        dst = out_dir / orig_name
        out_dir.mkdir(parents=True, exist_ok=True)

        # Remaining chunks: file content
        with dst.open("wb") as fout:
            while True:
                plaintext, nonce_int = _read_chunk(fin, aesgcm, nonce_int, src)
                if not plaintext:
                    break
                fout.write(plaintext)
                done += len(plaintext)
                _progress(done, src_size)

    print()
    return dst


# ── directory / single-file orchestration ──────────────────────────────────────

def process(mode: str, target: Path, out_root: Path | None, password: str) -> None:
    if target.is_file():
        if mode == "encrypt":
            stem         = target.stem
            parent       = target.parent
            enc_dir      = parent / f"{stem}_encrypted"
            archive_dir  = parent / f"{stem}_archival"
            enc_dir.mkdir(parents=True, exist_ok=True)
            archive_dir.mkdir(parents=True, exist_ok=True)

            fake = _unique_fake_name(enc_dir)
            dst  = enc_dir / fake
            print(f"  encrypting  {target}  →  {dst}")
            encrypt_file(target, dst, password)

            archive_dst = archive_dir / target.name
            target.rename(archive_dst)
            print(f"  archived    {target.name}  →  {archive_dst}")
        else:
            base = out_root if out_root else target.parent
            base.mkdir(parents=True, exist_ok=True)
            print(f"  decrypting  {target}  →  ", end="", flush=True)
            restored = decrypt_file(target, base, password)
            print(f"  restored as  {restored}")

    elif target.is_dir():
        # macOS creates hidden ._<name> AppleDouble metadata files alongside real files.
        # They contain only Finder attributes (labels, icons), never file content — skip them.
        files = sorted(p for p in target.rglob("*") if p.is_file() and not p.name.startswith("._"))

        if mode == "encrypt":
            enc_root     = target.parent / f"{target.name}_encrypted"
            archive_root = target.parent / f"{target.name}_archival"

            for f in files:
                rel      = f.relative_to(target)
                enc_dir  = enc_root / rel.parent
                arc_dir  = archive_root / rel.parent
                enc_dir.mkdir(parents=True, exist_ok=True)
                arc_dir.mkdir(parents=True, exist_ok=True)

                fake = _unique_fake_name(enc_dir)
                dst  = enc_dir / fake
                print(f"  encrypting  {f}  →  {dst}")
                try:
                    encrypt_file(f, dst, password)
                    arc_dst = arc_dir / f.name
                    f.rename(arc_dst)
                    print(f"  archived    {f.name}  →  {arc_dst}")
                except ValueError as e:
                    print(f"\n  skipping: {e}")
        else:
            for f in files:
                rel     = f.relative_to(target)
                out_dir = (out_root / rel.parent) if out_root else f.parent
                print(f"  decrypting  {f}  →  ", end="", flush=True)
                try:
                    restored = decrypt_file(f, out_dir, password)
                    print(f"restored as  {restored}")
                except ValueError as e:
                    print(f"\n  skipping: {e}")

        if not files:
            print("No files found.")
    else:
        raise FileNotFoundError(f"Not found: {target}")


# ── progress bar ───────────────────────────────────────────────────────────────

def _progress(done: int, total: int) -> None:
    if total == 0:
        return
    pct    = done * 100 // total
    bar    = "#" * (pct // 2) + "-" * (50 - pct // 2)
    mb_d   = done  / 1_048_576
    mb_t   = total / 1_048_576
    print(f"\r  [{bar}] {pct:3d}%  {mb_d:.1f}/{mb_t:.1f} MB", end="", flush=True)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode not in ("encrypt", "decrypt"):
        print(f"Unknown mode '{mode}'. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)

    target   = Path(sys.argv[2])
    # output_dir only applies to decrypt; encrypt auto-creates sibling folders
    out_root = Path(sys.argv[3]) if (len(sys.argv) > 3 and mode == "decrypt") else None

    password = getpass.getpass("Password: ")
    if mode == "encrypt":
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            sys.exit(1)

    try:
        process(mode, target, out_root, password)
        print("Done.")
    except (ValueError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
