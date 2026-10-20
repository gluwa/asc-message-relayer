//! Observer node binary entrypoint.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use observer_node::{Config, Server};
use tracing::debug;

#[derive(Parser, Debug)]
#[command(name = "observer-node")]
struct Cli {
    /// Verbose tracing (`debug` level).
    #[arg(short, long)]
    verbose: bool,

    /// YAML configuration (see `config.example.yaml`).
    #[arg(long, env = "OBSERVER_CONFIG_FILE")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if cli.verbose {
            tracing_subscriber::EnvFilter::new("debug,libp2p=info")
        } else {
            tracing_subscriber::EnvFilter::new("info")
        }
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config = Config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;
    debug!(?config, "configuration loaded");

    Server::new(config).run().await
}
