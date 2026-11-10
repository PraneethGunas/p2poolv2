// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Import public descriptors into a wallet tied to a P2Poolv2 Electrum
//! server's share chain.
//!
//! Import only orders the steps. The wallet checks the descriptors and owns
//! the database, including the saved Electrum config, and the Electrum module
//! reads the chain identity.

use crate::electrum::{ElectrumError, fetch_chain_identity};
use crate::{ElectrumConfig, Keychain, Wallet, WalletDescriptors, WalletError};
use bitcoin::Network;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

/// Errors produced when importing a wallet.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// A descriptor contains private keys, which an import would not save.
    #[error(
        "Import takes public descriptors only. The {0} descriptor contains private keys, which would not be saved"
    )]
    PrivateKey(Keychain),
    /// The descriptors or network were rejected, a file already exists at
    /// the wallet path, or the wallet could not be created.
    #[error(transparent)]
    Wallet(#[from] WalletError),
    /// The chain identity could not be read from the Electrum server.
    #[error(transparent)]
    Electrum(#[from] ElectrumError),
    /// The wallet path or its parent directory could not be accessed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Create a wallet at `path` from public descriptors, tied to the share chain
/// a P2Poolv2 Electrum server reports, and save `electrum_config` with it.
///
/// The network, the descriptors and the path are checked before the server is
/// contacted, and the server must be on `network`. Anything already at
/// `path`, including a dangling symbolic link or a wallet another import
/// created meanwhile, is reported as `WalletError::AlreadyExists` and left
/// unchanged. Missing parent directories are created, and stay if the import
/// fails. The wallet creates and cleans up its own file.
pub fn import_wallet(
    path: &Path,
    descriptor: &str,
    change_descriptor: Option<&str>,
    network: Network,
    electrum_config: &ElectrumConfig,
) -> Result<(), ImportError> {
    //* Check the network and descriptors, reject private keys, and refuse an occupied path, all before contacting the server.
    let descriptors = WalletDescriptors::parse(descriptor, change_descriptor, network)?;
    if let Some(keychain) = descriptors.keychain_with_private_keys() {
        return Err(ImportError::PrivateKey(keychain));
    }
    if path_is_occupied(path)? {
        return Err(ImportError::Wallet(WalletError::AlreadyExists));
    }

    //* Pin the share chain genesis the Electrum server reports for `network`.
    let chain = fetch_chain_identity(&electrum_config.url, network)?;

    //* Create the wallet with its Electrum config at `path`, then close it.
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory)?;
    }
    Wallet::create_from_descriptors(
        path,
        descriptors,
        chain.sharechain_genesis_hash,
        Some(electrum_config),
    )?;
    Ok(())
}

/// Whether anything, including a dangling symbolic link, exists at `path`.
fn path_is_occupied(path: &Path) -> Result<bool, ImportError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ImportError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::PrivateKey;
    use bitcoin::secp256k1::SecretKey;
    use std::num::NonZeroUsize;
    use tempfile::tempdir;

    const RECEIVE: &str = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";

    #[test]
    fn import_rejects_a_private_receive_descriptor_before_contacting_the_server() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let electrum_config = ElectrumConfig {
            url: "tcp://127.0.0.1:1".to_owned(),
            batch_size: NonZeroUsize::new(10).unwrap(),
        };
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let private = format!(
            "tr({})",
            PrivateKey::new(secret_key, Network::Signet).to_wif()
        );
        //* The private key is reported for the receive keychain, not as a connection failure, and nothing is created.
        assert!(matches!(
            import_wallet(&path, &private, None, Network::Signet, &electrum_config),
            Err(ImportError::PrivateKey(Keychain::Receive))
        ));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn import_rejects_an_occupied_path_and_leaves_the_file_unchanged() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let electrum_config = ElectrumConfig {
            url: "tcp://127.0.0.1:1".to_owned(),
            batch_size: NonZeroUsize::new(10).unwrap(),
        };
        fs::write(&path, b"not a wallet").unwrap();
        //* The path is reported as taken before the server is contacted, and the file keeps its bytes.
        assert!(matches!(
            import_wallet(&path, RECEIVE, None, Network::Signet, &electrum_config),
            Err(ImportError::Wallet(WalletError::AlreadyExists))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"not a wallet");
    }
}
