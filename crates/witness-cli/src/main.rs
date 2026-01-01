mod client;
mod commands;
mod freebird_client;
mod token_wallet;

use anyhow::Result;
use clap::{Parser, Subcommand};

use commands::{anchors, get, timestamp, token, verify};

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

        /// Path to Freebird token JSON file
        #[arg(long)]
        freebird_token: Option<String>,

        /// Base64-encoded Freebird token (alternative to --freebird-token)
        #[arg(long, conflicts_with = "freebird_token")]
        freebird_token_b64: Option<String>,

        /// Freebird issuer ID (required with --freebird-token-b64)
        #[arg(long, requires = "freebird_token_b64")]
        freebird_issuer: Option<String>,

        /// Freebird token expiration Unix timestamp (required with --freebird-token-b64)
        #[arg(long, requires = "freebird_token_b64")]
        freebird_exp: Option<u64>,

        /// Freebird token epoch (required with --freebird-token-b64)
        #[arg(long, requires = "freebird_token_b64")]
        freebird_epoch: Option<u32>,

        /// Freebird issuer URL to acquire token from (seamless flow)
        #[arg(long, conflicts_with_all = ["freebird_token", "freebird_token_b64"])]
        freebird_acquire: Option<String>,

        /// Use a token from the wallet (auto-selects available token)
        #[arg(long, conflicts_with_all = ["freebird_token", "freebird_token_b64", "freebird_acquire"])]
        freebird_wallet: bool,
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

    /// Manage Freebird token wallet
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Fetch tokens from an issuer and store in wallet
    Fetch {
        /// Freebird issuer URL
        #[arg(long)]
        issuer: String,

        /// Number of tokens to fetch
        #[arg(long, default_value = "10")]
        count: usize,
    },

    /// List tokens in the wallet
    List,

    /// Remove used and expired tokens
    Cleanup,

    /// Show wallet file path
    Path,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Timestamp {
            file,
            hash,
            output,
            save,
            freebird_token,
            freebird_token_b64,
            freebird_issuer,
            freebird_exp,
            freebird_epoch,
            freebird_acquire,
            freebird_wallet,
        } => {
            timestamp::run(
                &cli.gateway,
                file,
                hash,
                &output,
                save,
                freebird_token,
                freebird_token_b64,
                freebird_issuer,
                freebird_exp,
                freebird_epoch,
                freebird_acquire,
                freebird_wallet,
            )
            .await?;
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
        Commands::Token { action } => match action {
            TokenAction::Fetch { issuer, count } => {
                token::fetch(&issuer, count).await?;
            }
            TokenAction::List => {
                token::list().await?;
            }
            TokenAction::Cleanup => {
                token::cleanup().await?;
            }
            TokenAction::Path => {
                token::path().await?;
            }
        },
    }

    Ok(())
}
