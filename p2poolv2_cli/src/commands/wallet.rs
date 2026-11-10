// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Descriptor wallet commands, run against a P2Poolv2 Electrum server.

use crate::commands::WalletCommands;
use crate::commands::address::parse_network;
use bitcoin::Network;
use clap::{Args, ValueEnum, ValueHint};
use p2poolv2_wallet::import::{self, BackendConfig, import_wallet};
use std::env;
use std::error::Error;
use std::num::NonZeroUsize;
use std::path::PathBuf;

/// Options shared by every wallet command.
#[derive(Args, Debug)]
pub struct WalletOptions {
    /// Network of the wallet: main, testnet4, signet or regtest
    #[arg(short, long, value_parser = parse_network)]
    pub network: Network,
    /// Wallet data directory (default: ~/.p2poolv2_wallet)
    #[arg(short, long, value_hint = ValueHint::DirPath)]
    pub datadir: Option<PathBuf>,
    /// Wallet name: ASCII letters, digits, hyphens or underscores
    #[arg(short, long, value_parser = parse_wallet_name)]
    pub wallet: String,
}

/// Arguments of `wallet import`.
#[derive(Args, Debug)]
pub struct ImportArgs {
    #[command(flatten)]
    pub options: WalletOptions,
    /// Public receive descriptor, or a two-path descriptor for receive and change
    #[arg(long)]
    pub descriptor: String,
    /// Public change descriptor
    #[arg(long)]
    pub change_descriptor: Option<String>,
    /// Wallet backend type
    #[arg(long, value_enum, default_value = "electrum")]
    pub client_type: ClientType,
    /// Wallet database type
    #[arg(long, value_enum, default_value = "sqlite")]
    pub database_type: DatabaseType,
    /// Electrum server URL: tcp://HOST:PORT or ssl://HOST:PORT
    #[arg(short, long, value_hint = ValueHint::Url)]
    pub url: String,
    /// Maximum number of queries per Electrum batch
    #[arg(short, long, default_value = "10")]
    pub batch_size: NonZeroUsize,
}

/// Command line values of [`import::ClientType`].
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ClientType {
    Electrum,
}

impl From<ClientType> for import::ClientType {
    fn from(client_type: ClientType) -> Self {
        match client_type {
            ClientType::Electrum => Self::Electrum,
        }
    }
}

/// Command line values of [`import::DatabaseType`].
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DatabaseType {
    Sqlite,
}

impl From<DatabaseType> for import::DatabaseType {
    fn from(database_type: DatabaseType) -> Self {
        match database_type {
            DatabaseType::Sqlite => Self::Sqlite,
        }
    }
}

/// Execute a wallet command.
pub fn execute(command: &WalletCommands) -> Result<(), Box<dyn Error>> {
    match command {
        WalletCommands::Import(arguments) => execute_import(arguments),
    }
}

/// Import descriptors into a new wallet and print where it was saved.
fn execute_import(arguments: &ImportArgs) -> Result<(), Box<dyn Error>> {
    let path = wallet_path(&arguments.options)?;
    let backend = BackendConfig {
        client_type: arguments.client_type.into(),
        database_type: arguments.database_type.into(),
        url: arguments.url.clone(),
        batch_size: arguments.batch_size,
    };
    import_wallet(
        &path,
        &arguments.descriptor,
        arguments.change_descriptor.as_deref(),
        arguments.options.network,
        backend,
    )
    .map_err(|error| error.to_string())?;
    println!("Wallet saved at {}", path.display());
    Ok(())
}

/// Return the wallet database path, `<datadir>/<network>/<name>.sqlite`.
fn wallet_path(options: &WalletOptions) -> Result<PathBuf, Box<dyn Error>> {
    let datadir = match &options.datadir {
        Some(datadir) => datadir.clone(),
        None => env::home_dir()
            .ok_or("home directory is unavailable. Pass --datadir.")?
            .join(".p2poolv2_wallet"),
    };
    Ok(datadir
        .join(options.network.to_core_arg())
        .join(format!("{}.sqlite", options.wallet)))
}

/// Accept only ASCII letters, digits, hyphens and underscores, so a wallet name
/// cannot point outside the data directory.
fn parse_wallet_name(value: &str) -> Result<String, String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(
            "wallet names must contain only ASCII letters, digits, hyphens or underscores".into(),
        );
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands};
    use clap::{CommandFactory, Parser, error::ErrorKind};
    use std::path::Path;

    #[test]
    fn wallet_import_parses_options_and_defaults() {
        Cli::command().debug_assert();
        let parsed = Cli::try_parse_from([
            "p2poolv2_cli",
            "wallet",
            "import",
            "--network",
            "main",
            "--datadir",
            "/tmp/wallets",
            "-w",
            "alice",
            "--descriptor",
            "tr(key)",
            "-u",
            "tcp://127.0.0.1:50001",
        ])
        .unwrap();
        let Some(Commands::Wallet {
            command: WalletCommands::Import(arguments),
        }) = parsed.command
        else {
            panic!("wrong command")
        };
        assert_eq!(arguments.options.network, Network::Bitcoin);
        assert_eq!(arguments.batch_size.get(), 10);
        assert_eq!(
            wallet_path(&arguments.options).unwrap(),
            Path::new("/tmp/wallets/main/alice.sqlite")
        );
    }

    #[test]
    fn wallet_import_requires_network_and_wallet() {
        let missing_network = Cli::try_parse_from([
            "p2poolv2_cli",
            "wallet",
            "import",
            "-w",
            "alice",
            "--descriptor",
            "tr(key)",
            "-u",
            "tcp://127.0.0.1:50001",
        ])
        .unwrap_err();
        assert_eq!(missing_network.kind(), ErrorKind::MissingRequiredArgument);
        let missing_wallet = Cli::try_parse_from([
            "p2poolv2_cli",
            "wallet",
            "import",
            "-n",
            "signet",
            "--descriptor",
            "tr(key)",
            "-u",
            "tcp://127.0.0.1:50001",
        ])
        .unwrap_err();
        assert_eq!(missing_wallet.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn wallet_names_and_batch_sizes_are_validated() {
        let path_name = Cli::try_parse_from([
            "p2poolv2_cli",
            "wallet",
            "import",
            "-n",
            "signet",
            "-w",
            "../alice",
            "--descriptor",
            "tr(key)",
            "-u",
            "tcp://127.0.0.1:50001",
        ])
        .unwrap_err();
        assert_eq!(path_name.kind(), ErrorKind::ValueValidation);
        let zero_batch = Cli::try_parse_from([
            "p2poolv2_cli",
            "wallet",
            "import",
            "-n",
            "signet",
            "-w",
            "alice",
            "--descriptor",
            "tr(key)",
            "-u",
            "tcp://127.0.0.1:50001",
            "--batch-size",
            "0",
        ])
        .unwrap_err();
        assert_eq!(zero_batch.kind(), ErrorKind::ValueValidation);
    }
}
