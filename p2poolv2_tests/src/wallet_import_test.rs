// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for importing descriptors against the real Electrum
//! server, running on a confirmed test share chain.

use bitcoin::Network;
use p2poolv2_electrum::test_utils::start_test_server;
use p2poolv2_lib::test_utils::{build_confirmed_test_chain, setup_test_chain_store_handle};
use p2poolv2_wallet::import::import_wallet;
use p2poolv2_wallet::{ChainIdentity, ElectrumConfig, Wallet};
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
    let electrum_config = ElectrumConfig {
        url: format!("tcp://{address}"),
        batch_size: NonZeroUsize::new(10).unwrap(),
    };

    let import_path = path.clone();
    let import_electrum_config = electrum_config.clone();
    spawn_blocking(move || {
        import_wallet(
            &import_path,
            DESCRIPTOR,
            None,
            Network::Signet,
            &import_electrum_config,
        )
    })
    .await
    .unwrap()
    .unwrap();

    let chain = ChainIdentity {
        network: Network::Signet,
        sharechain_genesis_hash: blocks[0].block_hash(),
    };
    let wallet = Wallet::open(&path, chain).unwrap();
    assert_eq!(wallet.chain(), chain);
    assert_eq!(wallet.electrum_config().unwrap(), Some(electrum_config));
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    shutdown.cancel();
}
