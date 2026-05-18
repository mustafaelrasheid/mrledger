use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::rngs::OsRng;
use rand::thread_rng;
use rsa::{
    RsaPrivateKey,
    RsaPublicKey,
    pkcs8,
    Pkcs1v15Encrypt
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, DecodePublicKey};
use base64::engine::general_purpose;
use base64::{Engine, DecodeError};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};


pub fn encode64(input: &[u8]) -> String {
    return general_purpose::STANDARD
        .encode(input);
}

pub fn decode64(input: &str) -> Result<Vec<u8>, DecodeError> {
    return general_purpose::STANDARD
        .decode(input);
}

pub fn generate_key_pair() -> (String, String) {
    const BITS: usize = 2048;
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, BITS)
        .unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let private_pem = private_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .unwrap();
    let public_pem = public_key
        .to_public_key_pem(pkcs8::LineEnding::LF)
        .unwrap();
    
    return (
        public_pem.to_string(),
        private_pem.to_string()
    );
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

pub fn encrypt_key_aes(input: &[u8], key: &Key<Aes256Gcm>) -> Vec<u8> {
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);

    return Aes256Gcm::new(key)
        .encrypt(nonce, input)
        .unwrap();
}

pub fn encrypt_rsa(input: &[u8], public_key_str: &str) -> Vec<u8> {
    return RsaPublicKey::from_public_key_pem(public_key_str)
        .expect("Failed to parse public key")
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, input)
        .expect("Failed to encrypt");
}
