//! Token management commands

use anyhow::Result;
use crate::freebird_client::FreebirdIssuerClient;
use crate::token_wallet::TokenWallet;

/// Fetch tokens from an issuer and store them in the wallet
pub async fn fetch(issuer_url: &str, count: usize) -> Result<()> {
    println!("Fetching {} tokens from {}...", count, issuer_url);

    let mut client = FreebirdIssuerClient::new(issuer_url);

    // Initialize and get issuer info
    client.init().await?;
    let issuer_id = client.issuer_id().unwrap_or("unknown");
    println!("Issuer: {}", issuer_id);

    let mut wallet = TokenWallet::load()?;
    let mut success_count = 0;

    for i in 0..count {
        match client.issue_token().await {
            Ok(token) => {
                wallet.add_token(token);
                success_count += 1;
                print!("\r  Fetched {}/{} tokens", i + 1, count);
            }
            Err(e) => {
                eprintln!("\n  Failed to fetch token {}: {}", i + 1, e);
            }
        }
    }
    println!();

    wallet.save()?;
    println!(
        "Successfully stored {} tokens. Wallet now has {} available.",
        success_count,
        wallet.available_count(None)
    );

    Ok(())
}

/// List tokens in the wallet
pub async fn list() -> Result<()> {
    let wallet = TokenWallet::load()?;
    let tokens = wallet.list();

    if tokens.is_empty() {
        println!("No tokens in wallet.");
        println!();
        println!("Fetch tokens with: witness token fetch --issuer <URL> --count <N>");
        return Ok(());
    }

    let available = tokens.iter().filter(|t| !t.used && !t.expired).count();
    let used = tokens.iter().filter(|t| t.used).count();
    let expired = tokens.iter().filter(|t| t.expired && !t.used).count();

    println!("Token Wallet Status:");
    println!("  Available: {}", available);
    println!("  Used:      {}", used);
    println!("  Expired:   {}", expired);
    println!();

    if !tokens.is_empty() {
        println!("Tokens by issuer:");

        // Group by issuer
        let mut by_issuer: std::collections::HashMap<&str, Vec<_>> = std::collections::HashMap::new();
        for t in &tokens {
            by_issuer.entry(&t.issuer_id).or_default().push(t);
        }

        for (issuer, issuer_tokens) in by_issuer {
            let available = issuer_tokens
                .iter()
                .filter(|t| !t.used && !t.expired)
                .count();
            println!("  {}: {} available", issuer, available);
        }
    }

    Ok(())
}

/// Clean up used and expired tokens
pub async fn cleanup() -> Result<()> {
    let mut wallet = TokenWallet::load()?;
    let removed = wallet.cleanup();
    wallet.save()?;

    println!("Removed {} used/expired tokens.", removed);
    println!("Wallet now has {} available tokens.", wallet.available_count(None));

    Ok(())
}

/// Show wallet file path
pub async fn path() -> Result<()> {
    let path = TokenWallet::wallet_path()?;
    println!("{}", path.display());
    Ok(())
}
