//! safecrypt — Production-grade, reliability-focused file encryption CLI
//!
//! Design principles (priority order):
//! 1. Data safety & authenticity — AEAD on every chunk, authenticated last-chunk flag,
//!    truncation / reordering / bit-flip detection.
//! 2. No silent data loss — atomic writes (temp + fsync + rename), explicit --force.
//! 3. Secret hygiene — Zeroize on all key material and passphrases; never put secrets on argv.
//! 4. Streaming — constant ~1 MiB peak memory regardless of file size.
//! 5. Modern primitives only — Argon2id (memory-hard KDF) + XChaCha20-Poly1305 (AEAD).
//! 6. Fail closed — wrong passphrase, corruption, unexpected EOF → hard error with clear message.
//! 7. Future-proof header — magic + version so format can evolve safely.
//!
//! File format (version 1):
//!   MAGIC[4] = b"SFC1"
//!   VERSION[1] = 1
//!   SALT[16]          // random, for Argon2id
//!   BASE_NONCE[16]    // random, high half of every XChaCha nonce
//!   then zero or more chunks:
//!     FLAGS[1]        // bit0 = last chunk (must appear exactly once, at the end)
//!     CT_LEN[4 LE]
//!     CIPHERTEXT[CT_LEN]  // plaintext encrypted under XChaCha20-Poly1305 + 16-byte tag
//!
//! Nonce (24 bytes) = BASE_NONCE || counter.to_le_bytes()
//! AAD = FLAGS byte (binds the "last" flag into the Poly1305 tag)
//!
//! Empty files are a single last-chunk of zero-length plaintext.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"SFC1";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const BASE_NONCE_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const CHUNK_PLAIN_MAX: usize = 1024 * 1024;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + BASE_NONCE_LEN;

const ARGON2_M_KIB: u32 = 65536;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 4;

#[derive(Parser, Debug)]
#[command(
    name = "safecrypt",
    version = "1.0.0",
    about = "Reliable, production-grade file encryption (Argon2id + XChaCha20-Poly1305)",
    long_about = "Encrypts and decrypts files with strong authenticated encryption.\n\
Designed for data safety: streaming, atomic writes, zeroization of secrets,\n\
and detection of truncation / tampering / wrong passphrase."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,
        /// Output path (default: <input>.sfc)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite existing output without prompting
        #[arg(short, long)]
        force: bool,
        /// Delete the original file after successful encryption
        /// (NOT a secure wipe — just unlink. Use with care.)
        #[arg(long)]
        remove_original: bool,
        /// Read passphrase from file (first line only). Skips interactive prompt & confirm.
        /// Prefer this over argv for scripting; the file should be mode 0600.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Decrypt a file
    Decrypt {
        /// Input encrypted file
        input: PathBuf,
        /// Output path (default: strip .sfc suffix, or <input>.dec)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite existing output without prompting
        #[arg(short, long)]
        force: bool,
        /// Delete the encrypted file after successful decryption
        #[arg(long)]
        remove_original: bool,
        /// Read passphrase from file (first line only). Skips interactive prompt.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("{} {:#}", style("error:").red().bold(), e);
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt {
            input,
            output,
            force,
            remove_original,
            passphrase_file,
        } => {
            let output = output.unwrap_or_else(|| {
                let mut p = input.clone();
                p.set_extension(match p.extension().and_then(|e| e.to_str()) {
                    Some(ext) => format!("{ext}.sfc"),
                    None => "sfc".into(),
                });
                p
            });
            encrypt_file(&input, &output, force, remove_original, passphrase_file.as_deref())
        }
        Commands::Decrypt {
            input,
            output,
            force,
            remove_original,
            passphrase_file,
        } => {
            let output = output.unwrap_or_else(|| default_decrypt_output(&input));
            decrypt_file(&input, &output, force, remove_original, passphrase_file.as_deref())
        }
    }
}

fn default_decrypt_output(input: &Path) -> PathBuf {
    let s = input.to_string_lossy();
    if s.ends_with(".sfc") {
        PathBuf::from(&s[..s.len() - 4])
    } else {
        let mut p = input.to_path_buf();
        p.set_extension(match p.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.dec"),
            None => "dec".into(),
        });
        p
    }
}

fn read_password(confirm: bool, passphrase_file: Option<&Path>) -> Result<Zeroizing<String>> {
    if let Some(path) = passphrase_file {
        let content = fs::read_to_string(path)
            .with_context(|| format!("cannot read passphrase file {}", path.display()))?;
        let line = content.lines().next().unwrap_or("").trim_end_matches('\r');
        let pw = Zeroizing::new(line.to_owned());
        if pw.is_empty() {
            bail!("passphrase file is empty");
        }
        return Ok(pw);
    }
    let pw = Zeroizing::new(
        rpassword::prompt_password(format!("{} ", style("Passphrase:").cyan().bold())).context(
            "failed to read passphrase (is a TTY available? use --passphrase-file for scripts)",
        )?,
    );
    if pw.is_empty() {
        bail!("passphrase must not be empty");
    }
    if confirm {
        let pw2 = Zeroizing::new(
            rpassword::prompt_password(format!("{} ", style("Confirm:").cyan().bold()))
                .context("failed to read passphrase confirmation")?,
        );
        if *pw != *pw2 {
            bail!("passphrases do not match");
        }
    }
    Ok(pw)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))
        .map_err(|e| anyhow!("invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e}"))?;
    Ok(key)
}

fn write_header<W: Write>(
    w: &mut W,
    salt: &[u8; SALT_LEN],
    base_nonce: &[u8; BASE_NONCE_LEN],
) -> Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&[VERSION])?;
    w.write_all(salt)?;
    w.write_all(base_nonce)?;
    Ok(())
}

fn read_header<R: Read>(r: &mut R) -> Result<([u8; SALT_LEN], [u8; BASE_NONCE_LEN])> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)
        .context("failed to read magic (file too short or not a safecrypt file)")?;
    if &magic != MAGIC {
        bail!(
            "not a safecrypt file (bad magic: expected {:?}, got {:?})",
            MAGIC,
            magic
        );
    }
    let mut ver = [0u8; 1];
    r.read_exact(&mut ver).context("failed to read version")?;
    if ver[0] != VERSION {
        bail!(
            "unsupported safecrypt version: {} (this tool supports only {})",
            ver[0],
            VERSION
        );
    }
    let mut salt = [0u8; SALT_LEN];
    r.read_exact(&mut salt).context("failed to read salt")?;
    let mut base_nonce = [0u8; BASE_NONCE_LEN];
    r.read_exact(&mut base_nonce)
        .context("failed to read base nonce")?;
    Ok((salt, base_nonce))
}

fn make_nonce(base: &[u8; BASE_NONCE_LEN], counter: u64) -> XNonce {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[..BASE_NONCE_LEN].copy_from_slice(base);
    nonce_bytes[BASE_NONCE_LEN..].copy_from_slice(&counter.to_le_bytes());
    *XNonce::from_slice(&nonce_bytes)
}

struct AtomicWriter {
    final_path: PathBuf,
    tmp_path: PathBuf,
    file: Option<BufWriter<File>>,
}

impl AtomicWriter {
    fn create(final_path: &Path) -> Result<Self> {
        let parent = final_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        let tmp_name = format!(
            ".{}.safecrypt.tmp.{}",
            final_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("out"),
            hex::encode(suffix)
        );
        let tmp_path = parent.join(tmp_name);
        let file = File::create(&tmp_path)
            .with_context(|| format!("cannot create temporary file {}", tmp_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            final_path: final_path.to_path_buf(),
            tmp_path,
            file: Some(BufWriter::with_capacity(CHUNK_PLAIN_MAX + 64, file)),
        })
    }

    fn writer(&mut self) -> &mut BufWriter<File> {
        self.file.as_mut().expect("AtomicWriter already finished")
    }

    fn finish(mut self) -> Result<()> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| anyhow!("AtomicWriter already finished"))?;
        file.flush()
            .context("failed to flush temporary output")?;
        file.get_ref()
            .sync_all()
            .context("failed to fsync temporary output")?;
        drop(file);
        fs::rename(&self.tmp_path, &self.final_path).with_context(|| {
            format!(
                "failed to atomically replace {} with temporary file",
                self.final_path.display()
            )
        })?;
        if let Some(parent) = self.final_path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        self.tmp_path = PathBuf::new();
        Ok(())
    }
}

impl Drop for AtomicWriter {
    fn drop(&mut self) {
        self.file.take();
        if !self.tmp_path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

fn ensure_output_ok(path: &Path, force: bool) -> Result<()> {
    if path.exists() {
        if !force {
            bail!(
                "output file already exists: {}\n\
                 Use --force to overwrite, or choose a different -o path.",
                path.display()
            );
        }
        if path.is_dir() {
            bail!("output path is a directory: {}", path.display());
        }
    }
    Ok(())
}

fn ensure_input_ok(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("input file does not exist: {}", path.display());
    }
    if path.is_dir() {
        bail!("input path is a directory: {}", path.display());
    }
    Ok(())
}

fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    force: bool,
    remove_original: bool,
    passphrase_file: Option<&Path>,
) -> Result<()> {
    ensure_input_ok(input_path)?;
    ensure_output_ok(output_path, force)?;
    if input_path.canonicalize().ok() == output_path.canonicalize().ok() {
        bail!("refusing to encrypt in-place (input and output resolve to the same path)");
    }
    let password = read_password(true, passphrase_file)?;
    let meta = fs::metadata(input_path)
        .with_context(|| format!("cannot stat {}", input_path.display()))?;
    let total_size = meta.len();
    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; BASE_NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut base_nonce);
    let key = derive_key(&password, &salt)?;
    drop(password);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut input = BufReader::with_capacity(
        CHUNK_PLAIN_MAX,
        File::open(input_path)
            .with_context(|| format!("cannot open {} for reading", input_path.display()))?,
    );
    let mut atomic = AtomicWriter::create(output_path)?;
    {
        let out = atomic.writer();
        write_header(out, &salt, &base_nonce)?;
    }
    let pb = if total_size > 0 {
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░"),
        );
        pb
    } else {
        ProgressBar::hidden()
    };
    let mut buf_a = vec![0u8; CHUNK_PLAIN_MAX];
    let mut buf_b = vec![0u8; CHUNK_PLAIN_MAX];
    let mut n_cur = input
        .read(&mut buf_a)
        .context("error reading input file")?;
    let mut counter: u64 = 0;
    let mut bytes_done: u64 = 0;
    let mut using_a = true;
    loop {
        let (cur, next) = if using_a {
            (&buf_a[..], &mut buf_b[..])
        } else {
            (&buf_b[..], &mut buf_a[..])
        };
        let n_next = if n_cur == CHUNK_PLAIN_MAX {
            input.read(next).context("error reading input file")?
        } else {
            0
        };
        let is_last = n_next == 0;
        let flags: u8 = if is_last { 1 } else { 0 };
        let nonce = make_nonce(&base_nonce, counter);
        let aad = [flags];
        let plaintext = &cur[..n_cur];
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("encryption failed (internal error)"))?;
        {
            let out = atomic.writer();
            out.write_all(&[flags])?;
            out.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
            out.write_all(&ciphertext)?;
        }
        bytes_done += n_cur as u64;
        pb.set_position(bytes_done);
        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("file too large (chunk counter overflow)"))?;
        if is_last {
            break;
        }
        n_cur = n_next;
        using_a = !using_a;
    }
    buf_a.zeroize();
    buf_b.zeroize();
    pb.finish_and_clear();
    atomic.finish()?;
    println!(
        "{} Encrypted {} → {}",
        style("✓").green().bold(),
        input_path.display(),
        output_path.display()
    );
    if remove_original {
        fs::remove_file(input_path).with_context(|| {
            format!(
                "encryption succeeded but failed to remove original {}",
                input_path.display()
            )
        })?;
        println!(
            "{} Removed original {}",
            style("✓").green().bold(),
            input_path.display()
        );
    }
    Ok(())
}

fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    force: bool,
    remove_original: bool,
    passphrase_file: Option<&Path>,
) -> Result<()> {
    ensure_input_ok(input_path)?;
    ensure_output_ok(output_path, force)?;
    if input_path.canonicalize().ok() == output_path.canonicalize().ok() {
        bail!("refusing to decrypt in-place (input and output resolve to the same path)");
    }
    let password = read_password(false, passphrase_file)?;
    let mut input = BufReader::with_capacity(
        CHUNK_PLAIN_MAX + 64,
        File::open(input_path)
            .with_context(|| format!("cannot open {} for reading", input_path.display()))?,
    );
    let (salt, base_nonce) = read_header(&mut input)?;
    let key = derive_key(&password, &salt)?;
    drop(password);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let total_approx = fs::metadata(input_path)
        .map(|m| m.len().saturating_sub(HEADER_LEN as u64))
        .unwrap_or(0);
    let pb = if total_approx > 0 {
        let pb = ProgressBar::new(total_approx);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░"),
        );
        pb
    } else {
        ProgressBar::hidden()
    };
    let mut atomic = AtomicWriter::create(output_path)?;
    let mut counter: u64 = 0;
    let mut bytes_written: u64 = 0;
    let mut finished = false;
    loop {
        let mut flags_buf = [0u8; 1];
        match input.read_exact(&mut flags_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                if finished {
                    break;
                }
                bail!("truncated ciphertext (unexpected end of file before final chunk)");
            }
            Err(e) => return Err(e).context("error reading chunk flags"),
        }
        if finished {
            bail!("trailing data after final chunk (file may be corrupted)");
        }
        let flags = flags_buf[0];
        let is_last = flags & 1 != 0;
        if flags & !1 != 0 {
            bail!("invalid chunk flags (unsupported bits set)");
        }
        let mut len_buf = [0u8; 4];
        input
            .read_exact(&mut len_buf)
            .context("truncated ciphertext while reading chunk length")?;
        let ct_len = u32::from_le_bytes(len_buf) as usize;
        if ct_len < TAG_LEN {
            bail!(
                "invalid ciphertext length {} (smaller than authentication tag)",
                ct_len
            );
        }
        if ct_len > CHUNK_PLAIN_MAX + TAG_LEN {
            bail!(
                "chunk ciphertext length {} exceeds maximum allowed ({})",
                ct_len,
                CHUNK_PLAIN_MAX + TAG_LEN
            );
        }
        let mut ct_buf = vec![0u8; ct_len];
        input
            .read_exact(&mut ct_buf)
            .context("truncated ciphertext while reading chunk body")?;
        let nonce = make_nonce(&base_nonce, counter);
        let aad = [flags];
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ct_buf,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow!(
                    "decryption failed — wrong passphrase or corrupted / tampered ciphertext \
                     (chunk {})",
                    counter
                )
            })?;
        {
            let out = atomic.writer();
            out.write_all(&plaintext)
                .context("error writing decrypted data")?;
        }
        bytes_written += plaintext.len() as u64;
        pb.set_position(bytes_written.min(total_approx));
        ct_buf.zeroize();
        let mut plain_z = plaintext;
        plain_z.zeroize();
        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("chunk counter overflow"))?;
        if is_last {
            finished = true;
        }
    }
    if !finished {
        bail!("ciphertext ended without a final chunk");
    }
    pb.finish_and_clear();
    atomic.finish()?;
    println!(
        "{} Decrypted {} → {}",
        style("✓").green().bold(),
        input_path.display(),
        output_path.display()
    );
    if remove_original {
        fs::remove_file(input_path).with_context(|| {
            format!(
                "decryption succeeded but failed to remove encrypted file {}",
                input_path.display()
            )
        })?;
        println!(
            "{} Removed encrypted file {}",
            style("✓").green().bold(),
            input_path.display()
        );
    }
    Ok(())
}
