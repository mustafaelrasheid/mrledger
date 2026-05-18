mod args;
mod utils;
mod secret;
mod config;
mod error;

use std::process::exit;
use std::fs::{read_to_string, remove_file, write};
use std::env::var;
use clap::Parser;
use argon2::password_hash::{SaltString};
use aes_gcm::{Nonce, Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, Pkcs1v15Encrypt};
use crate::args::{Cli, Commands};
use crate::config::Config;
use crate::secret::Secret;
use crate::utils::{hash_password, decode64};

fn get_config(secrets_dir: &str) -> Config {
    let config = serde_json::from_str(
        &read_to_string(
            &format!("{}/config.json", secrets_dir)
        ).expect("Failed to read config file")
    ).expect("Invalid config file");

    return config;
}

fn get_secret(secrets_dir: &str, secret: &str) -> Secret {
    let secret = serde_json::from_str(
        &read_to_string(
            &format!("{}/{}.json", secrets_dir, secret)
        ).expect("Failed to read secret")
    ).expect("Invalid secret file");

    return secret;
}

fn put_secret(secrets_dir: &str, secret: &Secret) {
    write(
        &format!(
            "{}/{}.json",
            &secrets_dir,
            &secret.title
        ),
        serde_json::to_string_pretty(secret)
            .unwrap()
    ).expect("Failed to put secret")
}

fn main() {
    let secrets_dir = format!(
        "{}/secrets",
        var("HOME")
            .expect("No HOME veriable was set")
    );
    let cli = Cli::parse();

    match cli.command {
        Commands::Tell { title } => {
            let config = get_config(&secrets_dir);
            let content: String = dialoguer::Input::new()
                .with_prompt("What's on your mind?")
                .interact()
                .expect("Failed to get prompt");

            put_secret(
                &secrets_dir,
                &Secret::new(
                    &title,
                    &config.public_key,
                    &content
                )
            );
        },
        Commands::Remind { title } => {
            let config = get_config(&secrets_dir);
            let secret = get_secret(&secrets_dir, &title);
            let password: String = dialoguer::Password::new()
                .with_prompt("Key, please?")
                .interact()
                .expect("Failed to get key");
            let nonce_bytes = [0u8; 12];
            let key = RsaPrivateKey::from_pkcs8_pem(
                &String::from_utf8(
                    Aes256Gcm::new(
                        &hash_password(
                            &password,
                            &SaltString::from_b64(&config.salt)
                                .unwrap()
                        )
                    ).decrypt(
                        Nonce::from_slice(&nonce_bytes),
                        &*decode64(&config.private_key)
                            .expect("Invalid base64 encoding")
                    ).expect("Failed to decrypt private key")
                ).expect("Invalid UTF-8 in private key")
            ).expect("Failed to parse private key");
            let plaintext = String::from_utf8(
                key.decrypt(
                    Pkcs1v15Encrypt,
                    &decode64(&secret.content)
                        .expect("Invalid base64 encoding")
                ).expect("Failed to decrypt content")
            ).expect("Invalid UTF-8");
            
            print!("{}", title);
            if let Some(val) = secret.tag {
                println!(": {}", val);
            } else {
                println!("");
            }
            println!("{}", plaintext);
        },
        Commands::Forget { title } => {
            remove_file(
                &format!("{}/{}.json", &secrets_dir, &title)
            ).expect("Failed to remove secret");
        },
        Commands::Tag { title, tag } => {
            let mut secret = get_secret(&secrets_dir, &title);

            secret.tag = Some(tag);
            put_secret(&secrets_dir, &secret);
        }
        Commands::Setup => {
            let password: String = dialoguer::Password::new()
                .with_prompt("Password")
                .interact()
                .expect("Failed to get password");
            let confirm: String = dialoguer::Password::new()
                .with_prompt("Retyped password")
                .interact()
                .expect("Failed to get password");
            
            if password.as_str() != confirm.as_str() {
                println!("passwords don't match");
                exit(1);
            }
            write(
                &format!("{}/config.json", &secrets_dir),
                serde_json::to_string_pretty(&
                    Config::new(
                        &password
                    )
                ).unwrap()
            ).expect("Failed to put config file");
        }
    }
}
