use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mrledger")]
#[command(version)]
#[command(author = "mustafaelrasheid")]
#[command(
	about = "Somewhere to keep your secrets!",
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
	Forget {
		title: String,
	},
	Tag {
		title: String,
		tag: String
	},
	Setup,
}
