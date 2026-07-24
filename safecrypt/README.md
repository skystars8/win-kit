# safecrypt

Production-grade, reliability-focused file encryption CLI written in pure Rust.

## Design choices (why this is reliable)

### Cryptography
- **KDF**: Argon2id (PHC winner). Parameters: 64 MiB memory, 3 iterations, 4 lanes.
  Memory-hard → expensive for GPU/ASIC offline attacks while remaining interactive (~0.3–0.8 s).
- **AEAD**: XChaCha20-Poly1305
  - 256-bit key, 192-bit nonce (random 16-byte base + 64-bit counter) → nonce reuse is practically impossible.
  - Software-friendly, constant-time, no AES-NI dependency.
  - Poly1305 tag authenticates both plaintext and the "last-chunk" flag (via AAD).

### Streaming & memory safety
- Processes files in 1 MiB chunks. Peak RSS stays ~constant even for multi-GB inputs.
- Read-ahead buffer scheme so the encryptor always knows whether the current chunk is the last one (no empty trailing chunk for exact multiples of the chunk size).
- All secret material (`Zeroizing` + explicit `.zeroize()`) is wiped on drop.

### On-disk safety
- **Atomic writes**: every output goes to a randomly-named temporary file in the same directory, is `fsync`ed, then `rename`d over the final path. On crash you either have the old file or the complete new one — never a partial/corrupt mix.
- Temporary files are created with mode 0600 (Unix).
- Directory `fsync` after rename (best-effort durability of the directory entry).
- Refuses in-place encryption/decryption (same resolved path) to avoid partial overwrite disasters.
- Requires `--force` to overwrite an existing output.

### Integrity / anti-tampering
- Magic + version header → clear rejection of non-safecrypt files and future versions.
- Every chunk carries its own Poly1305 tag.
- The last-chunk flag is bound into the AAD of that chunk; decryptor demands exactly one last chunk and then EOF. Truncation, trailing garbage, reordering, or bit-flips all produce a hard error.
- Wrong passphrase is indistinguishable from corruption (same error message) — no oracle.

### CLI ergonomics & operational safety
- Passphrase never accepted on the command line (would appear in `ps`, shell history, audit logs).
- Interactive prompt (with confirmation on encrypt) or `--passphrase-file` (first line, for scripts/CI; file should be 0600).
- Progress bar for non-trivial files (indicatif).
- `--remove-original` is explicit and documented as *not* a secure wipe.
- Clear, actionable error messages (anyhow + thiserror style).

### File format (v1)
```
MAGIC     4 bytes  "SFC1"
VERSION   1 byte   1
SALT     16 bytes  random (Argon2)
BASE_NONCE 16 bytes random
── repeated ──
FLAGS     1 byte   bit0 = last
CT_LEN    4 bytes  little-endian length of following ciphertext
CIPHERTEXT N bytes XChaCha20-Poly1305 output (includes 16-byte tag)
```

Empty files are represented as a single last-chunk with zero-length plaintext.

## Build

```bash
cargo build --release
```

(Uses edition 2021 because the available toolchain is 1.75; the code itself is clean modern Rust.)

## Usage

```bash
# Encrypt (interactive passphrase, confirm)
./target/release/safecrypt encrypt secret.pdf

# Encrypt with output path and force
./target/release/safecrypt encrypt secret.pdf -o secret.pdf.sfc --force

# Non-interactive (scripts)
echo -n 'my strong passphrase' > /tmp/pw && chmod 600 /tmp/pw
./target/release/safecrypt encrypt secret.pdf --passphrase-file /tmp/pw --force
shred -u /tmp/pw   # or just rm

# Decrypt
./target/release/safecrypt decrypt secret.pdf.sfc
```

## What this deliberately does *not* do
- No public-key / multi-recipient mode (would require a different design, e.g. age).
- No compression (compress-then-encrypt is the user's responsibility if desired).
- No secure deletion of the original (impossible to do reliably across filesystems/SSDs; `--remove-original` is a plain unlink).
- No password strength meter (out of scope; use a password manager).

## Threat model (brief)
Protects confidentiality and integrity of files at rest against an attacker who can read or modify the ciphertext (disk theft, remote filesystem, backup leakage, etc.). Does not protect against an attacker who can already observe the running process memory or the passphrase entry itself.
