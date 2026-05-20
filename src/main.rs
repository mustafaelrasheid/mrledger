mod args;
mod utils;
mod secret;
mod config;
mod error;

use std::process::exit;
use std::fs::{read_to_string, remove_file, write, create_dir_all};
use std::env::var;
use clap::Parser;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, Oaep};
use sha2::Sha256;
use inquire::Text;
use inquire::validator::Validation;
use crate::args::{Cli, Commands};
use crate::config::Config;
use crate::secret::Secret;
use crate::utils::{hash_password, decode64, decrypt_aes};

trait ExpectOrExit<T> {
    fn expect_or_exit(self, msg: &str) -> T;
}

impl<T> ExpectOrExit<T> for Option<T> {
    fn expect_or_exit(self, msg: &str) -> T {
        return match self {
            Some(val) => val,
            None => {
                eprintln!("{}", msg);
                exit(1);
            }
        };
    }
}

impl<T, E: std::fmt::Display> ExpectOrExit<T> for Result<T, E> {
    fn expect_or_exit(self, msg: &str) -> T {
        return match self {
            Ok(val) => val,
            Err(e) => {
                eprintln!("{}: {}", msg, e);
                exit(1);
            }
        };
    }
}

fn get_config(secrets_dir: &str) -> Config {
    let config = serde_json::from_str(
        &read_to_string(
            &format!("{}/config.json", secrets_dir)
        ).expect_or_exit("Failed to read config file")
    ).expect_or_exit("Invalid config file");

    return config;
}

fn get_secret(secrets_dir: &str, secret: &str) -> Secret {
    let secret = serde_json::from_str(
        &read_to_string(
            &format!("{}/{}.json", secrets_dir, secret)
        ).expect_or_exit("Failed to read secret")
    ).expect_or_exit("Invalid secret file");

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
    ).expect_or_exit("Failed to put secret")
}

fn show_secret(secret: &Secret, plaintext: &str) {
    print!("{}", secret.title);
    if let Some(val) = &secret.tag {
        println!(": {}", val);
    } else {
        println!("");
    }
    println!("{}", plaintext);
}

fn main() {
    let secrets_dir = format!(
        "{}/secrets",
        var("HOME")
            .expect_or_exit("No HOME veriable was set")
    );
    let cli = Cli::parse();

    match cli.command {
        Commands::Tell { title } => {
            let config = get_config(&secrets_dir);
            let content: String = Text::new("What's on your mind?")
                .with_formatter(&|s| format!("{} ({}/180)", s, s.len()))
                .with_validator(|s: &str|{
                    if s.len() <= 185 {
                        return Ok(Validation::Valid);
                    } else {
                        return Ok(
                            Validation::Invalid(
                                "Message too long".into()
                            )
                        );
                    }
                })
                .prompt()
                .expect_or_exit("Failed to get prompt");

            put_secret(
                &secrets_dir,
                &Secret::new(
                    &title,
                    &config.public_key,
                    &content
                ).expect_or_exit("Failed to encrypt secret")
            );
        },
        Commands::Remind { title } => {
            let config = get_config(&secrets_dir);
            let secret = get_secret(&secrets_dir, &title);
            let password: String = dialoguer::Password::new()
                .with_prompt("Password, please?")
                .interact()
                .expect_or_exit("Failed to get key");
            let key = RsaPrivateKey::from_pkcs8_pem(
                &String::from_utf8(
                    decrypt_aes(
                        &hash_password(
                            &password,
                            &config
                                .get_salt()
                                .expect_or_exit("Invalid salt")
                        ),
                        decode64(&config.nonce)
                            .expect_or_exit("Invalid nonce")
                            .as_slice()
                            .try_into()
                            .expect_or_exit("Invalid nonce"),
                        &*decode64(&config.private_key)
                            .expect_or_exit("Invalid base64 encoding")
                    ).expect_or_exit("Failed to decrypt private key")
                ).expect_or_exit("Invalid UTF-8 in private key")
            ).expect_or_exit("Failed to parse private key");
            let plaintext = String::from_utf8(
                key.decrypt(
                    Oaep::new::<Sha256>(),
                    &decode64(&secret.content)
                        .expect_or_exit("Invalid base64 encoding")
                ).expect_or_exit("Failed to decrypt content")
            ).expect_or_exit("Invalid UTF-8");
            
            show_secret(&secret, &plaintext);
        },
        Commands::Forget { title } => {
            remove_file(
                &format!("{}/{}.json", &secrets_dir, &title)
            ).expect_or_exit("Failed to remove secret");
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
                .expect_or_exit("Failed to get password");
            let confirm: String = dialoguer::Password::new()
                .with_prompt("Retyped password")
                .interact()
                .expect_or_exit("Failed to get password");
            
            if password.as_str() != confirm.as_str() {
                println!("passwords don't match");
                exit(1);
            }
            create_dir_all(&secrets_dir)
                .expect_or_exit("Failed to create secrets directory");
            write(
                &format!("{}/config.json", &secrets_dir),
                serde_json::to_string_pretty(&
                    Config::new(
                        &password
                    )
                ).unwrap()
            ).expect_or_exit("Failed to put config file");
        }
    }
}
