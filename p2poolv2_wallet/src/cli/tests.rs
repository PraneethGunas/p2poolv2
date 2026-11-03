// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::args::{Cli, parse_fee_rate};
use super::commands::{Command, TxCommand, WalletCommand};
use super::wallet::{ImportError, WalletConfig, import_wallet};
use crate::{ChainIdentity, Wallet};
use bdk_wallet::KeychainKind;
use bdk_wallet::rusqlite::Connection;
use bitcoin::{BlockHash, Network};
use clap::{Parser, error::ErrorKind};
use std::{env, fs};
use tempfile::tempdir;

const ADDRESS: &str = "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x";
const RECEIVE: &str = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
const GENESIS: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn import_pins_electrum_identity_and_persists_wallet_configuration() {
    let directory = tempdir().unwrap();
    let url = env::var("P2POOL_ELECTRUM_URL").expect("run with just test-wallet");
    let parsed = Cli::try_parse_from([
        "p2pool-wallet",
        "--datadir",
        directory.path().to_str().unwrap(),
        "--wallet",
        "alice",
        "wallet",
        "import",
        "--ext-descriptor",
        RECEIVE,
        "--url",
        &url,
    ])
    .unwrap();
    parsed.validate().unwrap();
    let Command::Wallet(WalletCommand::Import(import)) = &parsed.command else {
        panic!("wrong action")
    };
    let path = import_wallet(&parsed, import).unwrap();
    assert_eq!(path, directory.path().join("signet/alice.sqlite"));
    let chain = ChainIdentity {
        network: Network::Signet,
        sharechain_genesis_hash: GENESIS.parse::<BlockHash>().unwrap(),
    };
    let reopened = Wallet::open(&path, chain).unwrap();
    assert_eq!(reopened.chain(), chain);
    assert!(
        reopened
            .public_descriptor(KeychainKind::External)
            .to_string()
            .starts_with(RECEIVE)
    );
    let connection = Connection::open(&path).unwrap();
    let encoded: String = connection
        .query_row(
            "SELECT config FROM p2pool_wallet_cli_config WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let config: WalletConfig = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        config.sharechain_genesis_hash,
        chain.sharechain_genesis_hash
    );
    assert_eq!(config.url, url);
    assert_eq!(config.batch_size, 10);
    assert!(matches!(
        import_wallet(&parsed, import),
        Err(ImportError::AlreadyExists)
    ));
}

#[test]
fn import_rejects_a_server_on_another_network_before_creating_wallet() {
    let directory = tempdir().unwrap();
    let url = env::var("P2POOL_ELECTRUM_URL").expect("run with just test-wallet");
    let parsed = Cli::try_parse_from([
        "p2pool-wallet",
        "--datadir",
        directory.path().to_str().unwrap(),
        "--wallet",
        "alice",
        "--network",
        "regtest",
        "wallet",
        "import",
        "--ext-descriptor",
        RECEIVE,
        "--url",
        &url,
    ])
    .unwrap();
    parsed.validate().unwrap();
    let Command::Wallet(WalletCommand::Import(import)) = &parsed.command else {
        panic!("wrong action")
    };
    assert!(matches!(
        import_wallet(&parsed, import),
        Err(ImportError::NetworkMismatch {
            expected: Network::Regtest,
            actual: Network::Signet,
        })
    ));
    assert!(!directory.path().join("regtest").exists());
}

#[test]
fn force_import_rejects_descriptor_changes_without_replacing_the_wallet() {
    let directory = tempdir().unwrap();
    let wallet_directory = directory.path().join("signet");
    fs::create_dir(&wallet_directory).unwrap();
    let path = wallet_directory.join("alice.sqlite");
    let chain = ChainIdentity {
        network: Network::Signet,
        sharechain_genesis_hash: GENESIS.parse().unwrap(),
    };
    let previous = Wallet::create(
        &path,
        "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        None,
        chain,
    )
    .unwrap()
    .public_descriptor(KeychainKind::External)
    .clone();
    let url = env::var("P2POOL_ELECTRUM_URL").expect("run with just test-wallet");
    let parsed = Cli::try_parse_from([
        "p2pool-wallet",
        "--datadir",
        directory.path().to_str().unwrap(),
        "--wallet",
        "alice",
        "wallet",
        "import",
        "--ext-descriptor",
        RECEIVE,
        "--url",
        &url,
        "--force",
    ])
    .unwrap();
    parsed.validate().unwrap();
    let Command::Wallet(WalletCommand::Import(import)) = &parsed.command else {
        panic!("wrong action")
    };
    assert!(matches!(
        import_wallet(&parsed, import),
        Err(ImportError::DescriptorMismatch)
    ));
    let reopened = Wallet::open(&path, chain).unwrap();
    assert_eq!(
        reopened.public_descriptor(KeychainKind::External),
        &previous
    );
}

#[test]
fn build_destinations_are_typed_positive_and_network_checked() {
    let parsed = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "--to",
        &format!("{ADDRESS}:10"),
        "--to",
        &format!("{ADDRESS}:20"),
        "-walice",
        "--drain-to",
        ADDRESS,
        "--fee-rate",
        "1.25",
        "--utxos",
        "0000000000000000000000000000000000000000000000000000000000000000:1",
    ])
    .unwrap();
    parsed.validate().unwrap();
    let Command::Tx(TxCommand::Build(arguments)) = parsed.command else {
        panic!("wrong action")
    };
    assert_eq!(arguments.recipients.len(), 2);
    assert_eq!(arguments.recipients[0].amount, 10);
    assert_eq!(arguments.recipients[1].amount, 20);
    assert_eq!(arguments.drain_to.unwrap().to_string(), ADDRESS);
    assert_eq!(arguments.fee_rate.unwrap().to_sat_per_kwu(), 313);
    assert_eq!(arguments.utxos.unwrap()[0].vout, 1);
    assert!(arguments.unspendable.is_none());

    let drain_only = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "--drain-to",
        ADDRESS,
        "-walice",
    ])
    .unwrap();
    let Command::Tx(TxCommand::Build(arguments)) = drain_only.command else {
        panic!("wrong action")
    };
    assert!(arguments.recipients.is_empty());
    assert!(arguments.drain_to.is_some());
    let missing = Cli::try_parse_from(["p2pool-wallet", "tx", "build", "-walice"])
        .err()
        .unwrap();
    assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
    let zero = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "-walice",
        "--to",
        &format!("{ADDRESS}:0"),
    ])
    .err()
    .unwrap();
    assert_eq!(zero.kind(), ErrorKind::ValueValidation);
    assert!(
        zero.to_string()
            .contains("recipient amount must be greater than zero")
    );
    let wrong_recipient_network = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "--to",
        &format!("{ADDRESS}:10"),
        "-walice",
        "--network",
        "regtest",
    ])
    .unwrap()
    .validate()
    .unwrap_err();
    assert_eq!(wrong_recipient_network.kind(), ErrorKind::ValueValidation);
    let wrong_drain_network = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "--drain-to",
        ADDRESS,
        "-walice",
        "--network",
        "regtest",
    ])
    .unwrap()
    .validate()
    .unwrap_err();
    assert_eq!(wrong_drain_network.kind(), ErrorKind::ValueValidation);
}

#[test]
fn wallet_and_psbt_requirements_follow_the_selected_operation() {
    let missing_wallet = Cli::try_parse_from(["p2pool-wallet", "balance", "show"])
        .unwrap()
        .validate()
        .unwrap_err();
    assert_eq!(missing_wallet.kind(), ErrorKind::MissingRequiredArgument);
    let inspect = Cli::try_parse_from([
        "p2pool-wallet",
        "psbt",
        "inspect",
        "--psbt.file",
        "nonexistent.psbt",
    ])
    .unwrap();
    assert!(inspect.wallet.is_none());
    inspect.validate().unwrap();
    let missing_source = Cli::try_parse_from(["p2pool-wallet", "psbt", "inspect"])
        .err()
        .unwrap();
    assert_eq!(missing_source.kind(), ErrorKind::MissingRequiredArgument);
    let ambiguous_source = Cli::try_parse_from([
        "p2pool-wallet",
        "psbt",
        "inspect",
        "--psbt.file",
        "input.psbt",
        "--psbt.hex",
        "00",
    ])
    .err()
    .unwrap();
    assert_eq!(ambiguous_source.kind(), ErrorKind::ArgumentConflict);
    let ambiguous_broadcast = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "broadcast",
        "--psbt.base64",
        "mock",
        "--tx.hex",
        "00",
        "-walice",
    ])
    .err()
    .unwrap();
    assert_eq!(ambiguous_broadcast.kind(), ErrorKind::ArgumentConflict);
    let broadcast = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "broadcast",
        "--tx.hex",
        "00",
        "-walice",
    ])
    .unwrap();
    assert_eq!(broadcast.command.name(), "tx broadcast");
}

#[test]
fn fee_rate_conversion_enforces_precision_and_range() {
    assert_eq!(parse_fee_rate(" 1.234 ").unwrap().to_sat_per_kwu(), 309);
    assert_eq!(parse_fee_rate("0.004").unwrap().to_sat_per_kwu(), 1);
    assert!(parse_fee_rate("0.0039").is_err());
    assert!(parse_fee_rate("NaN").is_err());
    assert!(parse_fee_rate("inf").is_err());
    assert!(parse_fee_rate("1e100").is_err());
}
