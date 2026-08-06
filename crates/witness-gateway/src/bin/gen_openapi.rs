//! OpenAPI generator for the client-facing gateway surface.
//!
//! Emits `docs/openapi.yaml` from the `#[utoipa::path]` annotations on the
//! client-facing handlers. The generated file is checked in and a drift test
//! (`server::openapi::tests::openapi_drift`) enforces zero diff.
//!
//! Run from the workspace root:
//!   cargo run -p witness-gateway --bin gen_openapi --features openapi

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = witness_gateway::server::openapi::to_yaml()?;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let repo_root = PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .canonicalize()?;
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    let out_path = docs_dir.join("openapi.yaml");

    std::fs::write(&out_path, yaml)?;
    println!("Wrote OpenAPI document to {}", out_path.display());
    Ok(())
}
