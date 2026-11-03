// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Descriptor import and local wallet configuration.

use super::args::Cli;
use super::commands::{ClientType, DatabaseType, ImportArgs};
use crate::{ChainIdentity, Wallet, WalletError};
use bdk_wallet::KeychainKind;
use bdk_wallet::descriptor::{DescriptorError, IntoWalletDescriptor};
use bdk_wallet::rusqlite::{Connection, Error as SqliteError, OpenFlags};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{BlockHash, Network};
use electrum_client::{Client, ConfigBuilder, ElectrumApi};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;

/// Failures while importing descriptors or saving wallet configuration.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("{0}")]
    InvalidInput(&'static str),
    #[error("wallet already exists; use --force to update its backend settings")]
    AlreadyExists,
    #[error("descriptors differ from the existing wallet; choose another wallet name")]
    DescriptorMismatch,
    #[error("Electrum server uses {actual}, but the wallet selected {expected}")]
    NetworkMismatch { expected: Network, actual: Network },
    #[error(transparent)]
    Descriptor(#[from] DescriptorError),
    #[error(transparent)]
    Wallet(#[from] WalletError),
    #[error(transparent)]
    Electrum(#[from] electrum_client::Error),
    #[error(transparent)]
    Storage(#[from] SqliteError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Backend settings and the chain identity pinned during import.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct WalletConfig {
    pub version: u32,
    pub network: Network,
    pub sharechain_genesis_hash: BlockHash,
    pub client_type: ClientType,
    pub database_type: DatabaseType,
    pub url: String,
    pub batch_size: usize,
}

/// Sharechain identity advertised by the Electrum server.
#[derive(Deserialize)]
struct ServerFeatures {
    genesis_hash: BlockHash,
    p2pool: P2PoolFeatures,
}

/// P2Pool network advertised alongside the server's standard Electrum fields.
#[derive(Deserialize)]
struct P2PoolFeatures {
    network: Network,
}

/// Create a wallet or update settings without replacing its descriptors or state.
pub(super) fn import_wallet(arguments: &Cli, import: &ImportArgs) -> Result<PathBuf, ImportError> {
    let name = arguments
        .wallet
        .as_deref()
        .ok_or(ImportError::InvalidInput("--wallet is required"))?;
    validate_public_descriptor(&import.ext_descriptor, arguments.network)?;
    if let Some(descriptor) = &import.int_descriptor {
        validate_public_descriptor(descriptor, arguments.network)?;
    }

    let datadir = match &arguments.datadir {
        Some(path) => path.clone(),
        None => env::home_dir()
            .ok_or(ImportError::InvalidInput(
                "home directory is unavailable; specify --datadir",
            ))?
            .join(".p2pool-wallet"),
    };
    let directory = datadir.join(arguments.network.to_string());
    let path = directory.join(format!("{name}.sqlite"));
    if path.try_exists()? && !import.force {
        return Err(ImportError::AlreadyExists);
    }

    let chain = fetch_chain_identity(&import.url, arguments.network)?;
    let config = WalletConfig {
        version: 1,
        network: chain.network,
        sharechain_genesis_hash: chain.sharechain_genesis_hash,
        client_type: import.client_type.clone(),
        database_type: import.database_type.clone(),
        url: import.url.clone(),
        batch_size: import.batch_size.get(),
    };

    fs::create_dir_all(&directory)?;
    let staged = NamedTempFile::new_in(&directory)?;
    let wallet = Wallet::create(
        staged.path(),
        &import.ext_descriptor,
        import.int_descriptor.as_deref(),
        chain,
    )?;

    if path.try_exists()? {
        if !import.force {
            return Err(ImportError::AlreadyExists);
        }
        let existing = Wallet::open(&path, chain)?;
        if existing.public_descriptor(KeychainKind::External)
            != wallet.public_descriptor(KeychainKind::External)
            || existing.public_descriptor(KeychainKind::Internal)
                != wallet.public_descriptor(KeychainKind::Internal)
        {
            return Err(ImportError::DescriptorMismatch);
        }
        save_config(&path, &config)?;
    } else {
        save_config(staged.path(), &config)?;
        drop(wallet);
        staged.persist_noclobber(&path).map_err(|error| {
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                ImportError::AlreadyExists
            } else {
                ImportError::Io(error.error)
            }
        })?;
    }
    Ok(path)
}

fn validate_public_descriptor(descriptor: &str, network: Network) -> Result<(), ImportError> {
    let (_, keys) = descriptor.into_wallet_descriptor(&Secp256k1::new(), network.into())?;
    if !keys.is_empty() {
        return Err(ImportError::InvalidInput(
            "import requires public descriptors; private key storage is not supported",
        ));
    }
    Ok(())
}

fn fetch_chain_identity(url: &str, expected: Network) -> Result<ChainIdentity, ImportError> {
    if !url.starts_with("tcp://") && !url.starts_with("ssl://") {
        return Err(ImportError::InvalidInput(
            "Electrum URL must be tcp://HOST:PORT or ssl://HOST:PORT",
        ));
    }
    let config = ConfigBuilder::new()
        .timeout(Some(Duration::from_secs(10)))
        .retry(0)
        .build();
    let response = Client::from_config(url, config)?.raw_call("server.features", [])?;
    let features: ServerFeatures = serde_json::from_value(response)?;
    if features.p2pool.network != expected {
        return Err(ImportError::NetworkMismatch {
            expected,
            actual: features.p2pool.network,
        });
    }
    Ok(ChainIdentity {
        network: features.p2pool.network,
        sharechain_genesis_hash: features.genesis_hash,
    })
}

fn save_config(path: &Path, config: &WalletConfig) -> Result<(), ImportError> {
    let encoded = serde_json::to_string(config)?;
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS p2pool_wallet_cli_config (
            id INTEGER PRIMARY KEY CHECK (id = 0),
            config TEXT NOT NULL
        )",
    )?;
    transaction.execute(
        "INSERT INTO p2pool_wallet_cli_config (id, config) VALUES (0, ?1)
         ON CONFLICT(id) DO UPDATE SET config = excluded.config",
        [encoded],
    )?;
    transaction.commit()?;
    Ok(())
}
