use base64::{engine::general_purpose, Engine as _};
use rust_string_encryptor::{
    decrypt_text, encrypt_text, encrypt_text_with, KdfParams, HEADER_BEGIN, HEADER_END, NONCE_LEN,
    PARAMS_LEN, SALT_LEN,
};

const PASSWORD: &str = "correct horse battery staple";

/// Cheap parameters for tests that don't care about KDF strength.
const FAST_KDF: KdfParams = KdfParams {
    m_cost: 64,
    t_cost: 1,
    p_cost: 1,
};

/// Produced by the V1 release (fixed Argon2 params, no AAD).
const V1_MESSAGE: &str = "-----BEGIN RUST-ENC V1-----\n\
    qwtevQVd6DXJMNykH91ef6y+oFExg2URd6Cn3ouTfp9nTzdYE2nLYRr62h9XrqBfSxEc9X9fjOEX0aXGJY7IFsA=\n\
    -----END RUST-ENC V1-----\n";

fn armor(data: &[u8]) -> String {
    format!(
        "{}\n{}\n{}\n",
        HEADER_BEGIN,
        general_purpose::STANDARD.encode(data),
        HEADER_END
    )
}

fn body(armored: &str) -> Vec<u8> {
    let b64: String = armored
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    general_purpose::STANDARD.decode(b64).unwrap()
}

#[test]
fn roundtrip() {
    let plaintext = "Привет, мир! 🔐 hello".as_bytes();
    let armored = encrypt_text(PASSWORD, plaintext).unwrap();
    assert!(armored.starts_with(HEADER_BEGIN));
    assert!(armored.trim_end().ends_with(HEADER_END));
    assert_eq!(&*decrypt_text(PASSWORD, &armored).unwrap(), plaintext);
}

#[test]
fn roundtrip_empty_plaintext() {
    let armored = encrypt_text_with(PASSWORD, b"", FAST_KDF).unwrap();
    assert!(decrypt_text(PASSWORD, &armored).unwrap().is_empty());
}

#[test]
fn decrypts_v1_messages() {
    let plaintext = decrypt_text("v1-password", V1_MESSAGE).unwrap();
    assert_eq!(&*plaintext, "legacy V1 message ✓".as_bytes());
}

#[test]
fn params_are_stored_in_message() {
    let custom = KdfParams {
        m_cost: 128,
        t_cost: 2,
        p_cost: 2,
    };
    let data = body(&encrypt_text_with(PASSWORD, b"secret", custom).unwrap());
    assert_eq!(data[0], 2, "format version");
    assert_eq!(data[1..5], 128u32.to_le_bytes());
    assert_eq!(data[5..9], 2u32.to_le_bytes());
    assert_eq!(data[9..13], 2u32.to_le_bytes());
    // Decrypt reads the params from the message, not from the defaults.
    assert_eq!(&*decrypt_text(PASSWORD, &armor(&data)).unwrap(), b"secret");
}

#[test]
fn long_output_is_line_wrapped() {
    let armored = encrypt_text_with(PASSWORD, &[b'x'; 500], FAST_KDF).unwrap();
    assert!(armored.lines().all(|l| l.len() <= 64));
}

#[test]
fn wrong_password_fails() {
    let armored = encrypt_text_with(PASSWORD, b"secret", FAST_KDF).unwrap();
    let err = decrypt_text("wrong", &armored).unwrap_err();
    assert!(err.to_string().contains("decryption failed"));
}

#[test]
fn salt_and_nonce_are_unique() {
    let a = body(&encrypt_text_with(PASSWORD, b"same", FAST_KDF).unwrap());
    let b = body(&encrypt_text_with(PASSWORD, b"same", FAST_KDF).unwrap());
    let salt = PARAMS_LEN..PARAMS_LEN + SALT_LEN;
    let nonce = PARAMS_LEN + SALT_LEN..PARAMS_LEN + SALT_LEN + NONCE_LEN;
    assert_ne!(a[salt.clone()], b[salt]);
    assert_ne!(a[nonce.clone()], b[nonce]);
}

#[test]
fn tampered_ciphertext_fails() {
    let mut data = body(&encrypt_text_with(PASSWORD, b"secret", FAST_KDF).unwrap());
    let last = data.len() - 1;
    data[last] ^= 0x01;
    assert!(decrypt_text(PASSWORD, &armor(&data)).is_err());
}

#[test]
fn tampered_params_fail() {
    let mut data = body(&encrypt_text_with(PASSWORD, b"secret", FAST_KDF).unwrap());
    data[5] = 2; // t_cost 1 -> 2: still valid params, but authenticated as AAD
    let err = decrypt_text(PASSWORD, &armor(&data)).unwrap_err();
    assert!(err.to_string().contains("decryption failed"));
}

#[test]
fn excessive_params_are_rejected() {
    let mut data = body(&encrypt_text_with(PASSWORD, b"secret", FAST_KDF).unwrap());
    data[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    let err = decrypt_text(PASSWORD, &armor(&data)).unwrap_err();
    assert!(err.to_string().contains("exceed"));
}

#[test]
fn excessive_params_rejected_on_encrypt() {
    let huge = KdfParams {
        m_cost: u32::MAX,
        ..FAST_KDF
    };
    assert!(encrypt_text_with(PASSWORD, b"secret", huge).is_err());
}

#[test]
fn unknown_version_is_rejected() {
    let mut data = body(&encrypt_text_with(PASSWORD, b"secret", FAST_KDF).unwrap());
    data[0] = 99;
    let err = decrypt_text(PASSWORD, &armor(&data)).unwrap_err();
    assert!(err.to_string().contains("unsupported format version"));
}

#[test]
fn surrounding_text_is_ignored() {
    let armored = encrypt_text_with(PASSWORD, b"secret", FAST_KDF).unwrap();
    let wrapped = format!("Hi,\nhere it is:\n\n{armored}\nBye!");
    assert_eq!(&*decrypt_text(PASSWORD, &wrapped).unwrap(), b"secret");
}

#[test]
fn rewrapped_base64_decodes() {
    let plaintext = vec![b'x'; 200];
    let data = body(&encrypt_text_with(PASSWORD, &plaintext, FAST_KDF).unwrap());
    let b64 = general_purpose::STANDARD.encode(&data);
    let wrapped: Vec<&str> = b64
        .as_bytes()
        .chunks(20)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let armored = format!(
        "{}\r\n{}\r\n{}\r\n",
        HEADER_BEGIN,
        wrapped.join("\r\n  "),
        HEADER_END
    );
    assert_eq!(&*decrypt_text(PASSWORD, &armored).unwrap(), &plaintext[..]);
}

#[test]
fn end_header_before_begin_does_not_panic() {
    let input = format!("{HEADER_END}\n{HEADER_BEGIN}\n");
    let err = decrypt_text(PASSWORD, &input).unwrap_err();
    assert!(err.to_string().contains("end header not found"));
}

#[test]
fn missing_headers_fail() {
    assert!(decrypt_text(PASSWORD, "garbage").is_err());
    assert!(decrypt_text(PASSWORD, HEADER_BEGIN).is_err());
}

#[test]
fn invalid_base64_fails() {
    let input = format!("{HEADER_BEGIN}\n!!!not base64!!!\n{HEADER_END}");
    let err = decrypt_text(PASSWORD, &input).unwrap_err();
    assert!(err.to_string().contains("base64"));
}

#[test]
fn data_shorter_than_tag_is_rejected() {
    // version + params + salt + nonce + 15 bytes: one byte short of a GCM tag.
    let mut data = vec![0u8; PARAMS_LEN + SALT_LEN + NONCE_LEN + 15];
    data[0] = 2;
    let err = decrypt_text(PASSWORD, &armor(&data)).unwrap_err();
    assert!(err.to_string().contains("too short"));
}
