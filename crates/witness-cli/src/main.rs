mod client;
mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

use commands::{anchors, get, log, timestamp, verify, verify_proof};

#[derive(Parser)]
#[command(name = "witness")]
#[command(about = "Witness timestamping CLI", long_about = None)]
#[command(version)]
struct Cli {
    /// Gateway URL
    #[arg(
        short,
        long,
        default_value = "http://localhost:8080",
        env = "WITNESS_GATEWAY"
    )]
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

    /// RFC 9162 Certificate Transparency v2 log operations
    Log {
        #[command(subcommand)]
        command: LogCommands,
    },

    /// Verify a full proof bundle (threshold sig + batch + cross-anchors + external anchors)
    VerifyProof {
        /// Path to a proof bundle JSON file (mutually exclusive with --hash)
        #[arg(long, conflicts_with = "hash")]
        bundle: Option<String>,

        /// Hash to fetch a proof bundle for from the gateway
        #[arg(long, conflicts_with = "bundle")]
        hash: Option<String>,

        /// Path to the home network's NetworkConfig JSON (offline verification)
        #[arg(long)]
        network_config: Option<String>,

        /// Path(s) to peer NetworkConfig JSON files for cross-anchor verification
        /// (repeatable; can be combined with --online to fall back to fetching)
        #[arg(long = "peer-config")]
        peer_config: Vec<String>,

        /// Fetch the home network config and any missing peer configs from gateways
        #[arg(long)]
        online: bool,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,
    },
}

#[derive(Subcommand)]
enum LogCommands {
    /// Fetch the gateway's latest Signed Tree Head
    Sth {
        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Verify threshold signatures against the gateway's network config
        #[arg(long)]
        verify: bool,
    },

    /// Fetch and (optionally) verify an RFC 9162 consistency proof
    Consistency {
        /// Smaller tree size (must match a published STH)
        #[arg(long)]
        first: u64,

        /// Larger tree size (must match a published STH)
        #[arg(long)]
        second: u64,

        /// Output format: json or text
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Verify the proof chain offline against the gateway's network config
        #[arg(long)]
        verify: bool,
    },
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
        } => {
            timestamp::run(&cli.gateway, file, hash, &output, save, freebird_token).await?;
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
        Commands::Log { command } => match command {
            LogCommands::Sth { output, verify } => {
                log::sth(&cli.gateway, &output, verify).await?;
            }
            LogCommands::Consistency {
                first,
                second,
                output,
                verify,
            } => {
                log::consistency(&cli.gateway, first, second, &output, verify).await?;
            }
        },
        Commands::VerifyProof {
            bundle,
            hash,
            network_config,
            peer_config,
            online,
            output,
        } => {
            verify_proof::run(
                &cli.gateway,
                bundle,
                hash,
                network_config,
                peer_config,
                online,
                &output,
            )
            .await?;
        }
    }

    Ok(())
}
