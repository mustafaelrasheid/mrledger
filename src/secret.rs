use serde::{Serialize, Deserialize};
use crate::utils::{encode64, encrypt_rsa};

#[derive(Serialize, Deserialize)]
pub struct Secret {
    pub title: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub encryption: String,
    pub encoding: String,
}

impl Secret {
    pub fn new(
        title: &str,
        public_key: &str,
        content: &str
    ) -> Self {
        return Self {
            title: title.to_string(),
            content: encode64(
                &encrypt_rsa(
                    content.as_bytes(),
                    public_key
                )
            ),
            tag: None,
            encryption: "RSA-2048".to_string(),
            encoding: "base64".to_string(),
        };
    }
}
