use anyhow::{Context, Result};
use witness_auditor::{audit, storage};
use clap::{Parser, Subcommand};
use std::time::Duration;
use tracing::{error, info};

use audit::{Auditor, TickResult};
use storage::Storage;

#[derive(Parser)]
#[command(name = "witness-auditor")]
#[command(about = "Independent auditor for witness gateway STH chains", long_about = None)]
#[command(version)]
struct Cli {
    /// Gateway URL to audit
    #[arg(short, long, env = "WITNESS_GATEWAY")]
    gateway: String,

    /// SQLite database path for auditor state
    #[arg(short, long, default_value = "witness-auditor.db", env = "WITNESS_AUDITOR_DB")]
    database: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a single audit check and exit
    Check,

    /// Poll the gateway continuously
    Watch {
        /// Poll interval in seconds
        #[arg(short, long, default_value = "60")]
        interval: u64,
    },

    /// Show the latest recorded STH and recent failures
    Status,

    /// Show recent recorded STHs
    History {
        /// Number of entries to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let storage = Storage::new(&cli.database)
        .await
        .with_context(|| format!("Failed to open database: {}", cli.database))?;
    storage.migrate().await?;

    match cli.command {
        Commands::Check => {
            let auditor = Auditor::new(&cli.gateway, storage);
            match auditor.tick().await? {
                TickResult::NoChange => {
                    println!("No change — latest STH matches stored state.");
                }
                TickResult::NewSth(sth) => {
                    println!(
                        "New STH accepted: tree_size={}, timestamp={}",
                        sth.tree_head.tree_size, sth.tree_head.timestamp
                    );
                }
                TickResult::Failed => {
                    eprintln!("Audit failed — see logs or run `status` for details.");
                    std::process::exit(1);
                }
            }
        }
        Commands::Watch { interval } => {
            let auditor = Auditor::new(&cli.gateway, storage);
            let duration = Duration::from_secs(interval);
            info!(
                "Starting watch loop for {} (interval: {}s)",
                cli.gateway, interval
            );
            loop {
                match auditor.tick().await {
                    Ok(TickResult::NoChange) => {}
                    Ok(TickResult::NewSth(sth)) => {
                        info!(
                            "New STH: tree_size={}, timestamp={}",
                            sth.tree_head.tree_size, sth.tree_head.timestamp
                        );
                    }
                    Ok(TickResult::Failed) => {
                        error!("Audit tick failed");
                    }
                    Err(e) => {
                        error!("Audit tick error: {}", e);
                    }
                }
                tokio::time::sleep(duration).await;
            }
        }
        Commands::Status => {
            if let Some(sth) = storage.latest_sth(&cli.gateway).await? {
                println!("Latest recorded STH for {}", cli.gateway);
                println!("  Tree size:  {}", sth.tree_head.tree_size);
                println!("  Timestamp:  {}", sth.tree_head.timestamp);
                println!(
                    "  Root hash:  {}",
                    hex::encode(sth.tree_head.root_hash)
                );
            } else {
                println!("No recorded STH for {}", cli.gateway);
            }

            let failures = storage.recent_failures(5).await?;
            if failures.is_empty() {
                println!("No recent failures.");
            } else {
                println!("Recent failures:");
                for f in failures {
                    println!(
                        "  [{}] {} at tree_size={:?}: {}",
                        f.detected_at, f.failure_type, f.tree_size, f.detail
                    );
                }
            }
        }
        Commands::History { limit } => {
            let sths = storage.recent_sths(limit).await?;
            if sths.is_empty() {
                println!("No recorded STHs.");
            } else {
                println!("Recent STHs for {}", cli.gateway);
                for (url, sth, audited_at) in sths {
                    println!(
                        "  [{}] {} size={} ts={} root={}",
                        audited_at,
                        url,
                        sth.tree_head.tree_size,
                        sth.tree_head.timestamp,
                        hex::encode(sth.tree_head.root_hash)
                    );
                }
            }
        }
    }

    Ok(())
}
