use anyhow::{anyhow, Context, Result};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aead::{Aead, Payload};
use argon2::{Argon2, Params};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const HEADER_BEGIN: &str = "-----BEGIN RUST-ENC V1-----";
pub const HEADER_END: &str = "-----END RUST-ENC V1-----";

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| anyhow!("invalid argon2 params: {:?}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow!("argon2 derive failed: {:?}", e))?;
    Ok(key)
}

pub fn encrypt_text(password: &str, plaintext: &[u8]) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let key_bytes = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*key_bytes)
        .map_err(|e| anyhow!("cipher init: {}", e))?;

    let nonce_gcm = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_gcm, Payload { msg: plaintext, aad: &[] })
        .map_err(|e| anyhow!("encryption failed: {:?}", e))?;

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    let b64 = general_purpose::STANDARD.encode(&out);
    let armored = format!("{}\n{}\n{}\n", HEADER_BEGIN, b64, HEADER_END);
    Ok(armored)
}

pub fn decrypt_text(password: &str, armored: &str) -> Result<Vec<u8>> {
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
    let cipher = Aes256Gcm::new_from_slice(&*key_bytes)
        .map_err(|e| anyhow!("cipher init: {}", e))?;
    let nonce_gcm = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce_gcm, Payload { msg: ciphertext, aad: &[] })
        .map_err(|_| anyhow!("decryption failed (bad password or corrupt data)"))?;

    Ok(plaintext)
}
