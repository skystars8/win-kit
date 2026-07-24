# threefish-cli

A simple, reliable command-line file encryption tool for Windows (and other platforms) using **Threefish-1024**.

Only the filename is required.  
- Any normal file → encrypted to `<filename>.enc`  
- Only `.enc` files can be decrypted (the `.enc` extension is stripped on success)

### Features

- **Threefish-1024** (1024-bit key / 1024-bit block) in CTR mode
- **Argon2id** password-based key derivation (memory-hard)
- **HMAC-SHA-512** authentication (Encrypt-then-MAC)
- Unique random salt + nonce (tweak) per file
- Atomic writes (temp file + rename) – no half-written output
- Secrets and password are zeroized after use
- Clear failure on wrong password or corrupted file (nothing is written)

### Build

Requires Rust 1.85+ (edition 2024).

```bash
cargo build --release
```

Binary: `target/release/threefish-cli` (or `threefish-cli.exe` on Windows)

### Usage

```text
threefish-cli <file>
```

**Encrypt**
```text
threefish-cli document.pdf
# → creates document.pdf.enc
```

**Decrypt**
```text
threefish-cli document.pdf.enc
# → restores document.pdf
```

You will be prompted for a password (and confirmation on encryption).

### File format (version 1)

```
[4 bytes]  Magic   "T3F1"
[1 byte]   Version 1
[32 bytes] Salt
[16 bytes] Nonce / Threefish tweak
[variable] Ciphertext (CTR)
[64 bytes] HMAC-SHA-512 tag
```

---

## Reliability Assessment

**Yes — for its intended purpose it is solid and reliable**, with a few clear caveats.

### What is done well (the reliability-critical parts)

| Aspect | Status | Why it matters |
|--------|--------|----------------|
| **Authenticated encryption** | Correct | Encrypt-then-MAC with HMAC-SHA-512 over header + ciphertext. Wrong password or any corruption is detected *before* any plaintext is written. |
| **MAC-first design** | Correct | You never get a partially decrypted or silently corrupted file. |
| **Key derivation** | Strong | Argon2id (memory-hard) with a random 32-byte salt per file. |
| **Nonce / tweak** | Correct | Fresh 16-byte random value used as Threefish tweak every time → no keystream reuse. |
| **Mode of operation** | Correct | Manual CTR with a full 128-byte big-endian counter. No padding → original length is preserved exactly. |
| **Atomic writes** | Correct | Write to temp file → `fsync` → rename. Crash or power loss cannot leave a half-written result. |
| **Secret handling** | Good | Key material and password are zeroized. |
| **File format rules** | Clear | Only `.enc` files can be decrypted; non-`.enc` → encrypt. |

These are the parts that actually determine whether decryption will succeed or fail safely. They are implemented correctly.

### Realistic caveats

1. **Threefish-1024 is uncommon**  
   The algorithm itself is sound (designed by the Skein team, heavily analyzed during the SHA-3 competition). However:
   - Far fewer independent implementations and less real-world battle-testing than AES.
   - The Rust crate is marked “hazmat” for a reason — it is a raw block cipher. We wrapped it properly, but the ecosystem around it is thinner.

2. **Security is dominated by the passphrase**  
   A 1024-bit key is overkill. The real strength is Argon2id + your password. A weak password will be the weak link no matter how exotic the cipher is.

3. **Whole-file-in-memory**  
   Large files (multi-GB) will consume a lot of RAM. For typical documents, photos, etc. this is fine; for huge archives it is not ideal.

4. **Manual CTR**  
   I implemented it carefully (big-endian 128-byte counter, unique tweak). It is correct, but any hand-rolled mode is always a place where subtle bugs *could* hide. Using a well-audited AEAD (e.g. AES-256-GCM or ChaCha20-Poly1305) would remove this residual risk.

5. **No formal security audit**  
   This is a carefully written personal tool, not a audited library.

### Bottom-line assessment

- **For personal offline file encryption** (documents, backups, sensitive files you control): **Yes, it is reliable.**  
  The design choices that matter for “will it decrypt correctly or fail cleanly?” are done properly. Wrong password or bit-flipped file will refuse to decrypt instead of giving you garbage.

- **For high-stakes or long-term archival use** (or if you want maximum future-proofing and auditability): I would prefer a widely-used AEAD such as **AES-256-GCM** or **XChaCha20-Poly1305** with the same Argon2id + authenticated construction. Those have far more scrutiny and ready-made, audited crates.

So: the app is good and trustworthy for the use case. The uncommon choice of Threefish-1024 is the main aesthetic/ecosystem risk, not a correctness risk in the code itself.
