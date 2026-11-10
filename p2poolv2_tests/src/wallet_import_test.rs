// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for importing descriptors against the real Electrum
//! server, running on a confirmed test share chain.

use bitcoin::Network;
use p2poolv2_electrum::test_utils::start_test_server;
use p2poolv2_lib::test_utils::{build_confirmed_test_chain, setup_test_chain_store_handle};
use p2poolv2_wallet::electrum::ElectrumError;
use p2poolv2_wallet::import::{
    BackendConfig, ClientType, DatabaseType, ImportError, import_wallet,
};
use p2poolv2_wallet::{ChainIdentity, Wallet};
use std::fs;
use std::num::NonZeroUsize;
use tempfile::tempdir;
use tokio::task::spawn_blocking;
use tokio_util::sync::CancellationToken;

/// Public BIP86 test-network key, as a two-path descriptor for receive and change.
const DESCRIPTOR: &str = "tr([c55b303f/86'/1'/0']tpubDCiHofpEs47kx358bPdJmTZHmCDqQ8qw32upCSxHrSEdeeBs2T5Mq6QMB2ukeMqhNBiyhosBvJErteVhfURPGXPv3qLJPw5MVpHUewsbP2m/<0;1>/*)";

#[tokio::test]
async fn import_creates_a_wallet_pinned_to_the_served_chain() {
    let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
    let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
    let shutdown = CancellationToken::new();
    let (address, _server) = start_test_server(chain_store_handle, shutdown.clone()).await;
    let directory = tempdir().unwrap();
    let path = directory.path().join("signet").join("alice.sqlite");
    let backend = BackendConfig {
        client_type: ClientType::Electrum,
        database_type: DatabaseType::Sqlite,
        url: format!("tcp://{address}"),
        batch_size: NonZeroUsize::new(10).unwrap(),
    };

    let import_path = path.clone();
    spawn_blocking(move || import_wallet(&import_path, DESCRIPTOR, None, Network::Signet, backend))
        .await
        .unwrap()
        .unwrap();

    let chain = ChainIdentity {
        network: Network::Signet,
        sharechain_genesis_hash: blocks[0].block_hash(),
    };
    assert_eq!(Wallet::open(&path, chain).unwrap().chain(), chain);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    shutdown.cancel();
}

#[tokio::test]
async fn import_against_another_network_leaves_no_wallet() {
    let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
    build_confirmed_test_chain(&chain_store_handle, 1).await;
    let shutdown = CancellationToken::new();
    let (address, _server) = start_test_server(chain_store_handle, shutdown.clone()).await;
    let directory = tempdir().unwrap();
    let path = directory.path().join("alice.sqlite");
    let backend = BackendConfig {
        client_type: ClientType::Electrum,
        database_type: DatabaseType::Sqlite,
        url: format!("tcp://{address}"),
        batch_size: NonZeroUsize::new(10).unwrap(),
    };

    let result =
        spawn_blocking(move || import_wallet(&path, DESCRIPTOR, None, Network::Testnet4, backend))
            .await
            .unwrap();

    assert!(matches!(
        result,
        Err(ImportError::Electrum(ElectrumError::NetworkMismatch {
            expected: Network::Testnet4,
            actual: Network::Signet,
        }))
    ));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    shutdown.cancel();
}

#[tokio::test]
async fn concurrent_imports_of_one_wallet_create_it_once() {
    let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
    let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
    let shutdown = CancellationToken::new();
    let (address, _server) = start_test_server(chain_store_handle, shutdown.clone()).await;
    let directory = tempdir().unwrap();
    let path = directory.path().join("alice.sqlite");
    let backend = BackendConfig {
        client_type: ClientType::Electrum,
        database_type: DatabaseType::Sqlite,
        url: format!("tcp://{address}"),
        batch_size: NonZeroUsize::new(10).unwrap(),
    };

    let first_path = path.clone();
    let first_backend = backend.clone();
    let first = spawn_blocking(move || {
        import_wallet(
            &first_path,
            DESCRIPTOR,
            None,
            Network::Signet,
            first_backend,
        )
    });
    let second_path = path.clone();
    let second = spawn_blocking(move || {
        import_wallet(&second_path, DESCRIPTOR, None, Network::Signet, backend)
    });
    let outcomes = (first.await.unwrap(), second.await.unwrap());

    assert!(matches!(
        outcomes,
        (Ok(()), Err(ImportError::AlreadyExists)) | (Err(ImportError::AlreadyExists), Ok(()))
    ));
    let chain = ChainIdentity {
        network: Network::Signet,
        sharechain_genesis_hash: blocks[0].block_hash(),
    };
    assert_eq!(Wallet::open(&path, chain).unwrap().chain(), chain);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    shutdown.cancel();
}
