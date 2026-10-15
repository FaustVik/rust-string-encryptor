use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Format version (1 byte) + Argon2 m_cost, t_cost, p_cost (u32 LE each).
pub const PARAMS_LEN: usize = 13;

pub const HEADER_BEGIN: &str = "-----BEGIN RUST-ENC V2-----";
pub const HEADER_END: &str = "-----END RUST-ENC V2-----";
pub const HEADER_BEGIN_V1: &str = "-----BEGIN RUST-ENC V1-----";
pub const HEADER_END_V1: &str = "-----END RUST-ENC V1-----";

const FORMAT_VERSION: u8 = 2;
const BASE64_LINE_LEN: usize = 64;

// Upper bounds accepted on decrypt, so a crafted message can't make us
// allocate gigabytes of memory or spin for minutes before failing.
const MAX_M_COST: u32 = 1 << 20; // 1 GiB
const MAX_T_COST: u32 = 32;
const MAX_P_COST: u32 = 16;

/// Argon2id cost parameters. V2 messages carry them, so the defaults can be
/// raised later without breaking old ciphertexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    fn validate(&self) -> Result<()> {
        if self.m_cost > MAX_M_COST || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST {
            bail!("argon2 parameters exceed allowed limits: {:?}", self);
        }
        Ok(())
    }
}

pub fn derive_key(password: &str, salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow!("invalid argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow!("argon2 derive failed: {}", e))?;
    Ok(key)
}

pub fn encrypt_text(password: &str, plaintext: &[u8]) -> Result<String> {
    encrypt_text_with(password, plaintext, KdfParams::default())
}

pub fn encrypt_text_with(password: &str, plaintext: &[u8], kdf: KdfParams) -> Result<String> {
    kdf.validate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| anyhow!("rng failed: {}", e))?;
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("rng failed: {}", e))?;

    let mut out = Vec::with_capacity(PARAMS_LEN + SALT_LEN + NONCE_LEN + plaintext.len() + TAG_LEN);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&kdf.m_cost.to_le_bytes());
    out.extend_from_slice(&kdf.t_cost.to_le_bytes());
    out.extend_from_slice(&kdf.p_cost.to_le_bytes());

    let ciphertext = seal(password, kdf, &salt, &nonce, plaintext, &out)?;
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    let b64 = general_purpose::STANDARD.encode(&out);
    let mut armored = String::with_capacity(b64.len() + b64.len() / BASE64_LINE_LEN + 64);
    armored.push_str(HEADER_BEGIN);
    armored.push('\n');
    for line in b64.as_bytes().chunks(BASE64_LINE_LEN) {
        // base64 output is pure ASCII, so every chunk is valid UTF-8.
        armored.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        armored.push('\n');
    }
    armored.push_str(HEADER_END);
    armored.push('\n');
    Ok(armored)
}

pub fn decrypt_text(password: &str, armored: &str) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(data) = extract_body(armored, HEADER_BEGIN, HEADER_END)? {
        decrypt_v2(password, &data)
    } else if let Some(data) = extract_body(armored, HEADER_BEGIN_V1, HEADER_END_V1)? {
        decrypt_v1(password, &data)
    } else {
        bail!("begin header not found")
    }
}

/// Returns the decoded body between `begin` and `end`, or `None` when `begin`
/// is absent (so the caller can try another format version).
fn extract_body(armored: &str, begin: &str, end: &str) -> Result<Option<Vec<u8>>> {
    let Some(begin_idx) = armored.find(begin) else {
        return Ok(None);
    };
    let body_start = begin_idx + begin.len();
    // Search for the end header only after the begin header, so a stray END
    // placed before BEGIN can't produce an inverted slice range (panic).
    let body_len = armored[body_start..]
        .find(end)
        .ok_or_else(|| anyhow!("end header not found"))?;
    // Drop all whitespace so line-wrapped base64 (e.g. from email) still decodes.
    let between: String = armored[body_start..body_start + body_len]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let data = general_purpose::STANDARD
        .decode(between)
        .context("base64 decode failed")?;
    Ok(Some(data))
}

fn decrypt_v2(password: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < PARAMS_LEN + SALT_LEN + NONCE_LEN + TAG_LEN {
        bail!("decoded data too short");
    }
    if data[0] != FORMAT_VERSION {
        bail!("unsupported format version {}", data[0]);
    }
    let u32_at = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().expect("4 bytes"));
    let kdf = KdfParams {
        m_cost: u32_at(1),
        t_cost: u32_at(5),
        p_cost: u32_at(9),
    };
    kdf.validate()?;

    // The version + params prefix is authenticated as AAD, so it can't be
    // altered without decryption failing.
    let (aad, rest) = data.split_at(PARAMS_LEN);
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    open(password, kdf, salt, nonce, ciphertext, aad)
}

fn decrypt_v1(password: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        bail!("decoded data too short");
    }
    let (salt, rest) = data.split_at(SALT_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    // V1 always used the default parameters and no AAD.
    open(password, KdfParams::default(), salt, nonce, ciphertext, &[])
}

fn cipher_for(password: &str, kdf: KdfParams, salt: &[u8]) -> Result<Aes256Gcm> {
    let key = derive_key(password, salt, kdf)?;
    Aes256Gcm::new_from_slice(&*key).map_err(|e| anyhow!("cipher init: {}", e))
}

fn seal(
    password: &str,
    kdf: KdfParams,
    salt: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = Nonce::try_from(nonce).map_err(|_| anyhow!("invalid nonce length"))?;
    cipher_for(password, kdf, salt)?
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow!("encryption failed: {}", e))
}

fn open(
    password: &str,
    kdf: KdfParams,
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let nonce = Nonce::try_from(nonce).map_err(|_| anyhow!("invalid nonce length"))?;
    let plaintext = cipher_for(password, kdf, salt)?
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("decryption failed (bad password or corrupt data)"))?;
    Ok(Zeroizing::new(plaintext))
}
