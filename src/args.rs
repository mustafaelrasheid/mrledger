use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mrledger")]
#[command(version = "0.1.0")]
#[command(author = "mustafaelrasheid")]
#[command(
    about = "somewhere for secrets",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Tell {
        title: String,
    },
    Remind {
        title: String,
    },
    Setup
}
