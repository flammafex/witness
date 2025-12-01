mod client;
mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

use commands::{anchors, get, timestamp, verify, verify_federation};

#[derive(Parser)]
#[command(name = "witness")]
#[command(about = "Witness timestamping CLI", long_about = None)]
#[command(version)]
struct Cli {
    /// Gateway URL
    #[arg(short, long, default_value = "http://localhost:8080", env = "WITNESS_GATEWAY")]
    gateway: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Timestamp a file or hash
    Timestamp {
        /// File path to timestamp (will compute SHA-256)
        #[arg(short, long, conflicts_with = "hash")]
        file: Option<String>,

        /// Hash to timestamp (hex encoded SHA-256)
        #[arg(long, conflicts_with = "file")]
        hash: Option<String>,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Save attestation to file
        #[arg(short, long)]
        save: Option<String>,
    },

    /// Get an existing timestamp by hash
    Get {
        /// Hash to look up (hex encoded SHA-256)
        hash: String,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,
    },

    /// Verify a signed attestation
    Verify {
        /// Path to attestation JSON file
        file: String,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,
    },

    /// Show gateway configuration
    Config {},

    /// Show external anchor proofs for an attestation
    Anchors {
        /// Hash to look up (hex encoded SHA-256)
        hash: String,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,
    },

    /// Verify federated attestation with full trust chain
    VerifyFederation {
        /// Hash to verify (hex encoded SHA-256)
        hash: String,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Timestamp { file, hash, output, save } => {
            timestamp::run(&cli.gateway, file, hash, &output, save).await?;
        }
        Commands::Get { hash, output } => {
            get::run(&cli.gateway, &hash, &output).await?;
        }
        Commands::Verify { file, output } => {
            verify::run(&cli.gateway, &file, &output).await?;
        }
        Commands::Config {} => {
            let client = client::WitnessClient::new(&cli.gateway);
            let config = client.get_config().await?;
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        Commands::Anchors { hash, output } => {
            anchors::run(&cli.gateway, &hash, &output).await?;
        }
        Commands::VerifyFederation { hash, output } => {
            verify_federation::run(&cli.gateway, &hash, &output).await?;
        }
    }

    Ok(())
}
