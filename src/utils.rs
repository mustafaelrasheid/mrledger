use aes_gcm::{Aes256Gcm, KeyInit, Key, Nonce};
use aes_gcm::aead::Aead;
use base64::engine::general_purpose;
use base64::Engine;
use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::password_hash::{SaltString};

pub fn encode64(input: &[u8]) -> String {
    return general_purpose::STANDARD.encode(input);
}

pub fn decode64(input: &str) -> Vec<u8> {
    return general_purpose::STANDARD.decode(input).unwrap();
}

pub fn hash_password(password: &str, salt: &SaltString)
-> Key<Aes256Gcm> {
    let argon2 = Argon2::default();
    let password_salt_hash = argon2.hash_password(
        password.as_bytes(),
        salt
    ).unwrap();
    let hashed_bytes = password_salt_hash.hash.unwrap();
    let binding = hashed_bytes.as_bytes();
    let early_bytes: [u8; 32] = binding[..32].try_into().unwrap();
    let key = Key::<Aes256Gcm>::from(early_bytes);
    
    return key;
}

