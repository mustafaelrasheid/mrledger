use aes_gcm::{Aes256Gcm, Key};
use serde::{Serialize, Deserialize};
use rsa::RsaPublicKey;
use rand::rngs::OsRng;
use rsa::Pkcs1v15Encrypt;
use rsa::pkcs8::DecodePublicKey;
use crate::utils::encode64;

#[derive(Serialize, Deserialize)]
pub struct Secret {
    pub title: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    pub encryption: String,
    pub encoding: String,
}

fn encrypt(input: &[u8], public_key_str: &str) -> Vec<u8> {
    return RsaPublicKey::from_public_key_pem(public_key_str)
        .expect("Failed to parse public key")
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, input)
        .expect("Failed to encrypt");
}

impl Secret {
    pub fn new(
        title: &str,
        public_key: &str,
        content: &str
    ) -> Self {
        return Self {
            title: title.to_string(),
            content: encode64(&encrypt(content.as_bytes(), public_key)),
            description: None,
            hint: None,
            encryption: "RSA-2048".to_string(),
            encoding: "base64".to_string(),
        };
    }
}
