use rand::thread_rng;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString};
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use aes_gcm::Key;
use aes_gcm::Nonce;
use serde::{Serialize, Deserialize};
use crate::utils::{encode64, hash_password};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub public_key: String,
    pub private_key: String,
    pub salt: String,
    pub private_key_encryption: String,
}

fn generate_keys() -> (String, String) {
    const BITS: usize = 2048;
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, BITS)
        .expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);
    let private_pem = private_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .expect("Failed to encode private key");
    let public_pem = public_key
        .to_public_key_pem(pkcs8::LineEnding::LF)
        .expect("Failed to encode public key");
    
    return (public_pem.to_string(), private_pem.to_string());
}


fn encrypt_key(input: &[u8], key: &Key<Aes256Gcm>) -> Vec<u8> {
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, input).unwrap();

    return ciphertext;
}

impl Config {
    pub fn new(
        password: &str
    ) -> Self {
        let salt = SaltString::generate(rand::thread_rng());
        let (public_key, private_key) = generate_keys();
        let hashed_password = hash_password(&password, &salt);

        return Self {
            public_key: public_key,
            private_key: encode64(
                &encrypt_key(
                    private_key.as_bytes(),
                    &hashed_password
                )
            ),
            salt: salt.to_string(),
            private_key_encryption: "Argon+AES".to_string()
        };
    }
}
