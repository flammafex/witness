mod client;
mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

use commands::{anchors, anonymous, get, proof, subscribe, timestamp, verify};

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

    /// Submit an anonymous timestamp using a Freebird token
    Anonymous {
        /// File path to timestamp (will compute SHA-256)
        #[arg(short, long, conflicts_with = "hash")]
        file: Option<String>,

        /// Hash to timestamp (hex encoded SHA-256)
        #[arg(long, conflicts_with = "file")]
        hash: Option<String>,

        /// Freebird VOPRF token (base64url encoded)
        #[arg(short, long)]
        token: String,

        /// Token expiration timestamp (Unix seconds)
        #[arg(short, long)]
        exp: i64,

        /// Token epoch (for MAC key derivation)
        #[arg(long)]
        epoch: u32,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Save attestation to file
        #[arg(short, long)]
        save: Option<String>,
    },

    /// Get merkle proof for offline/light client verification
    Proof {
        /// Hash to get proof for (hex encoded SHA-256)
        #[arg(long, conflicts_with = "file")]
        hash: Option<String>,

        /// Verify a saved proof file offline (no network required)
        #[arg(short, long, conflicts_with = "hash")]
        file: Option<String>,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Save proof to file
        #[arg(short, long)]
        save: Option<String>,
    },

    /// Subscribe to real-time notifications via WebSocket
    Subscribe {
        /// Notification types to subscribe to (attestation, batch, anchor)
        /// If not specified, subscribes to all types
        #[arg(short, long, value_delimiter = ',')]
        types: Vec<String>,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Exit after receiving N notifications
        #[arg(short, long)]
        count: Option<usize>,
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
        Commands::Anonymous { file, hash, token, exp, epoch, output, save } => {
            anonymous::run(&cli.gateway, file, hash, token, exp, epoch, &output, save).await?;
        }
        Commands::Proof { hash, file, output, save } => {
            if let Some(proof_file) = file {
                // Offline verification from saved proof file
                proof::verify_from_file(&proof_file, &output)?;
            } else if let Some(hash_str) = hash {
                // Fetch proof from gateway
                proof::run(&cli.gateway, &hash_str, &output, save.as_deref(), false).await?;
            } else {
                anyhow::bail!("Either --hash or --file must be provided");
            }
        }
        Commands::Subscribe { types, output, count } => {
            subscribe::run(&cli.gateway, &types, &output, count).await?;
        }
    }

    Ok(())
}
