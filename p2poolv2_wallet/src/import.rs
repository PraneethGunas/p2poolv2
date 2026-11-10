// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Import public descriptors into a wallet tied to a P2Poolv2 Electrum
//! server's share chain.

use crate::electrum::{ElectrumError, fetch_chain_identity};
use crate::{Wallet, WalletError, expected_hrp};
use bdk_wallet::descriptor::{DescriptorError, IntoWalletDescriptor};
use bdk_wallet::rusqlite::{Connection, Error as SqliteError, OpenFlags};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{BlockHash, Network};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::num::NonZeroUsize;
use std::path::Path;
use tempfile::NamedTempFile;

/// Errors produced when importing a wallet.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// A descriptor contains private keys, which an import would not save.
    #[error("Import takes public descriptors only, private keys would not be saved")]
    PrivateKey,
    /// A wallet already exists at the path.
    #[error("A wallet already exists at this path")]
    AlreadyExists,
    /// A descriptor could not be parsed.
    #[error(transparent)]
    Descriptor(#[from] DescriptorError),
    /// The wallet could not be created or opened.
    #[error(transparent)]
    Wallet(#[from] WalletError),
    /// The chain identity could not be read from the Electrum server.
    #[error(transparent)]
    Electrum(#[from] ElectrumError),
    /// SQLite could not save the wallet configuration.
    #[error(transparent)]
    Storage(#[from] SqliteError),
    /// The wallet configuration could not be encoded as JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The wallet path could not be accessed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Client used to sync the wallet.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    /// A P2Poolv2 Electrum server.
    Electrum,
}

/// Storage used for wallet state.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    /// A SQLite database file.
    Sqlite,
}

/// Backend settings saved with an imported wallet.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackendConfig {
    pub client_type: ClientType,
    pub database_type: DatabaseType,
    /// Electrum server URL, `tcp://HOST:PORT` or `ssl://HOST:PORT`.
    pub url: String,
    /// Maximum number of queries per Electrum batch.
    pub batch_size: NonZeroUsize,
}

/// Backend settings and chain identity, saved in the wallet database.
#[derive(Debug, Deserialize, Serialize)]
struct WalletConfig {
    version: u32,
    network: Network,
    sharechain_genesis_hash: BlockHash,
    #[serde(flatten)]
    backend: BackendConfig,
}

/// Create a wallet at `path` from public descriptors, failing if one already
/// exists there.
///
/// The Electrum server must be on `network`. The wallet is tied to the share
/// chain the server reports. Missing parent directories are created.
pub fn import_wallet(
    path: &Path,
    descriptor: &str,
    change_descriptor: Option<&str>,
    network: Network,
    backend: BackendConfig,
) -> Result<(), ImportError> {
    //* Reject an unsupported network, private keys, or an existing wallet.
    expected_hrp(network).map_err(WalletError::from)?;
    validate_public_descriptor(descriptor, network)?;
    if let Some(change_descriptor) = change_descriptor {
        validate_public_descriptor(change_descriptor, network)?;
    }
    if path.try_exists()? {
        return Err(ImportError::AlreadyExists);
    }

    //* Pin the network and share chain genesis the Electrum server reports.
    let chain = fetch_chain_identity(&backend.url, network)?;
    let config = WalletConfig {
        version: 1,
        network: chain.network,
        sharechain_genesis_hash: chain.sharechain_genesis_hash,
        backend,
    };

    //* Build the wallet in a temporary file, so a failed import leaves nothing behind.
    let directory = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(directory)?;
    let staged = NamedTempFile::new_in(directory)?;
    let wallet = Wallet::create(staged.path(), descriptor, change_descriptor, chain)?;
    save_config(staged.path(), &config)?;
    drop(wallet);

    //* Move the wallet into place, failing if another import created it meanwhile.
    staged.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == io::ErrorKind::AlreadyExists {
            ImportError::AlreadyExists
        } else {
            ImportError::Io(error.error)
        }
    })?;
    Ok(())
}

/// Reject a descriptor that carries private keys.
fn validate_public_descriptor(descriptor: &str, network: Network) -> Result<(), ImportError> {
    let (_, keys) = descriptor.into_wallet_descriptor(&Secp256k1::new(), network.into())?;
    if !keys.is_empty() {
        return Err(ImportError::PrivateKey);
    }
    Ok(())
}

/// Save the backend settings and chain identity in the wallet database.
fn save_config(path: &Path, config: &WalletConfig) -> Result<(), ImportError> {
    let encoded = serde_json::to_string(config)?;
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS p2poolv2_wallet_config (
            id INTEGER PRIMARY KEY CHECK (id = 0),
            config TEXT NOT NULL
        )",
    )?;
    transaction.execute(
        "INSERT INTO p2poolv2_wallet_config (id, config) VALUES (0, ?1)
         ON CONFLICT(id) DO UPDATE SET config = excluded.config",
        [encoded],
    )?;
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::PrivateKey;
    use bitcoin::secp256k1::SecretKey;
    use tempfile::tempdir;

    const RECEIVE: &str = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";

    #[test]
    fn import_rejects_private_keys_and_existing_wallets_before_contacting_the_server() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let backend = BackendConfig {
            client_type: ClientType::Electrum,
            database_type: DatabaseType::Sqlite,
            url: "tcp://127.0.0.1:1".to_owned(),
            batch_size: NonZeroUsize::new(10).unwrap(),
        };
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let private = format!(
            "tr({})",
            PrivateKey::new(secret_key, Network::Signet).to_wif()
        );
        assert!(matches!(
            import_wallet(&path, &private, None, Network::Signet, backend.clone()),
            Err(ImportError::PrivateKey)
        ));
        assert!(!path.exists());
        fs::write(&path, b"").unwrap();
        assert!(matches!(
            import_wallet(&path, RECEIVE, None, Network::Signet, backend),
            Err(ImportError::AlreadyExists)
        ));
    }
}
