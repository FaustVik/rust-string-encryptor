use anyhow::{anyhow, Context, Result};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aead::{Aead, Payload};
use argon2::{Argon2, Params};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rpassword::read_password;
use std::io::{Read, Write};
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; // AES-GCM standard
const HEADER_BEGIN: &str = "-----BEGIN RUST-ENC V1-----";
const HEADER_END: &str = "-----END RUST-ENC V1-----";

#[derive(Parser)]
#[command(author, version, about = "Encrypt/decrypt short secrets using password (AES-256-GCM + Argon2id)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a string (reads from stdin if no --text provided)
    Encrypt {
        /// text to encrypt (optional). If omitted, read from stdin.
        #[arg(short, long)]
        text: Option<String>,
    },
    /// Decrypt a block (reads armored block from stdin if no --text provided)
    Decrypt {
        /// armored block (optional). If omitted, read from stdin.
        #[arg(short, long)]
        text: Option<String>,
    },
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    // Argon2id params: moderate-ish cost; tune as needed
    let params = Params::new(65536, 3, 1, Some(32)) // memory_kib, iterations, parallelism, output_size
        .context("invalid argon2 params")?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .context("argon2 derive failed")?;
    Ok(key)
}

fn encrypt_text(password: &str, plaintext: &[u8]) -> Result<String> {
    // generate salt + nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let key_bytes = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| anyhow!("cipher init: {}", e))?;

    let nonce_gcm = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_gcm, Payload { msg: plaintext, aad: &[] })
        .context("encryption failed")?;

    // wipe key material
    let mut key_zero = key_bytes;
    key_zero.zeroize();

    // layout: SALT || NONCE || CIPHERTEXT
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    let b64 = general_purpose::STANDARD.encode(&out);
    let armored = format!("{}\n{}\n{}\n", HEADER_BEGIN, b64, HEADER_END);
    Ok(armored)
}

fn decrypt_text(password: &str, armored: &str) -> Result<Vec<u8>> {
    // extract base64 between headers
    let begin_idx = armored.find(HEADER_BEGIN).ok_or_else(|| anyhow!("begin header not found"))?;
    let end_idx = armored.find(HEADER_END).ok_or_else(|| anyhow!("end header not found"))?;
    let between = &armored[begin_idx + HEADER_BEGIN.len()..end_idx].trim();
    let data = general_purpose::STANDARD
        .decode(between)
        .context("base64 decode failed")?;
    if data.len() < SALT_LEN + NONCE_LEN + 1 {
        return Err(anyhow!("decoded data too short"));
    }
    let salt = &data[0..SALT_LEN];
    let nonce = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let key_bytes = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| anyhow!("cipher init: {}", e))?;
    let nonce_gcm = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce_gcm, Payload { msg: ciphertext, aad: &[] })
        .context("decryption failed (bad password or corrupt)" )?;

    // wipe
    let mut key_zero = key_bytes;
    key_zero.zeroize();

    Ok(plaintext)
}

fn read_stdin_to_string() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).context("read stdin")?;
    Ok(s)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Encrypt { text } => {
            let input = match text {
                Some(t) => t,
                None => read_stdin_to_string()?,
            };
            // trim trailing newline if pasted
            let input = input.trim_end_matches('\n');
            eprint!("Enter passphrase: ");
            let pass = read_password()?;
            let armored = encrypt_text(&pass, input.as_bytes())?;
            // ensure pass doesn't linger
            let mut p = pass;
            p.zeroize();

            println!("{}", armored);
        }
        Commands::Decrypt { text } => {
            let input = match text {
                Some(t) => t,
                None => read_stdin_to_string()?,
            };
            eprint!("Enter passphrase: ");
            let pass = read_password()?;
            let plaintext = decrypt_text(&pass, &input)?;
            let mut p = pass;
            p.zeroize();

            // print raw plaintext to stdout
            std::io::stdout().write_all(&plaintext)?;
            std::io::stdout().write_all(b"\n")?;
        }
    }

    Ok(())
}