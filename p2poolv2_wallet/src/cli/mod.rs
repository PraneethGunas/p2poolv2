// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet commands, argument validation, and shell completions.

mod args;
mod commands;
mod wallet;

#[cfg(test)]
mod tests;

use args::Cli;
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use commands::{Command, CompletionCommand, WalletCommand};
use std::io::{self, Write};
use thiserror::Error;

/// CLI failures after successful argument parsing.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("{command}: not implemented")]
    NotImplemented { command: &'static str },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Import(#[from] wallet::ImportError),
}

/// Parse arguments and execute the selected command.
pub fn run() -> Result<(), CliError> {
    let arguments = Cli::parse();
    arguments.validate().unwrap_or_else(|error| error.exit());
    match &arguments.command {
        Command::Completion(CompletionCommand::Generate { shell }) => {
            let mut script = Vec::new();
            generate(*shell, &mut Cli::command(), "p2pool-wallet", &mut script);
            io::stdout().lock().write_all(&script)?;
            Ok(())
        }
        Command::Wallet(WalletCommand::Import(import)) => {
            let path = wallet::import_wallet(&arguments, import)?;
            writeln!(io::stdout().lock(), "Wallet saved at {}", path.display())?;
            Ok(())
        }
        _ => Err(CliError::NotImplemented {
            command: arguments.command.name(),
        }),
    }
}
