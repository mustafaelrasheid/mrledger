use aes_gcm::{Aes256Gcm, Key};
use base64::engine::general_purpose;
use base64::{Engine, DecodeError};
use argon2::Argon2;
use argon2::PasswordHasher;
use argon2::password_hash::{SaltString};

pub fn encode64(input: &[u8]) -> String {
    return general_purpose::STANDARD
        .encode(input);
}

pub fn decode64(input: &str) -> Result<Vec<u8>, DecodeError> {
    return general_purpose::STANDARD
        .decode(input);
}

pub fn hash_password(password: &str, salt: &SaltString)
-> Key<Aes256Gcm> {
    let argon2 = Argon2::default();
    let password_salt_hash = argon2.hash_password(
        password.as_bytes(),
        salt
    ).unwrap().hash.unwrap();
    let early_bytes: [u8; 32] = password_salt_hash
        .as_bytes()[..32]
        .try_into()
        .unwrap();
    let key = Key::<Aes256Gcm>::from(early_bytes);
    
    return key;
}

