use serde::{Serialize, Deserialize};
use argon2::password_hash::{SaltString, Error as Argon2Error};
use crate::utils::{
    encode64,
    generate_key_pair,
    hash_password,
    encrypt_key_aes
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub public_key: String,
    pub private_key: String,
    pub salt: String,
    pub nonce: String,
    pub private_key_encryption: String,
}

impl Config {
    pub fn new(
        password: &str
    ) -> Self {
        let salt = SaltString::generate(rand::thread_rng());
        let (public_key, private_key) = generate_key_pair();
        let hashed_password = hash_password(&password, &salt);
        let (encrypted_key, nonce) = encrypt_key_aes(
            private_key.as_bytes(),
            &hashed_password
        );

        return Self {
            public_key: public_key,
            private_key: encode64(
                &encrypted_key
            ),
            nonce: encode64(&nonce),
            salt: salt.to_string(),
            private_key_encryption: "Argon+AES".to_string()
        };
    }

    pub fn get_salt(&self) -> Result<SaltString, Argon2Error> {
        return SaltString::from_b64(&self.salt);
    }
}
