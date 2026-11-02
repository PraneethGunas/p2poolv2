// Copyright (c) 2026 The P2Poolv2 developers
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Electrum mock serving fixed responses over newline-delimited TCP JSON-RPC.
//!
//! Run with `cargo run -p p2poolv2_wallet --example electrum`.
//! An optional port argument overrides the default port of 50001.
//! Port zero selects an available port, printed after binding.
//! Append `-- COMMAND [ARGS...]` to serve requests while a command runs.
//! The command receives the server URL in `P2POOL_ELECTRUM_URL`.

use serde::Deserialize;
use serde_json::{Value, json};
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;

const GENESIS_HASH: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const MAX_REQUEST_BYTES: u64 = 65_536;
const SERVER_NAME: &str = "p2pool-electrum-mock";
const PROTOCOL_VERSION: &str = "1.4";

#[derive(Deserialize)]
struct Request {
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Requests {
    Single(Request),
    Batch(Vec<Request>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VersionRequest {
    Single(String),
    MinMax(String, String),
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1).peekable();
    let port = if arguments.peek().is_some_and(|argument| argument != "--") {
        arguments.next().unwrap().to_string_lossy().parse::<u16>()?
    } else {
        50001
    };
    let command = match arguments.next() {
        Some(separator) if separator == "--" => {
            Some(arguments.next().ok_or("expected a command after --")?)
        }
        Some(_) => return Err("usage: electrum [PORT] [-- COMMAND [ARGS...]]".into()),
        None => None,
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    let url = format!("tcp://{}", listener.local_addr()?);
    println!("{url}");
    io::stdout().flush()?;

    if let Some(command) = command {
        thread::spawn(move || {
            if let Err(error) = serve(listener) {
                eprintln!("Electrum mock: {error}");
            }
        });
        let status = Command::new(command)
            .args(arguments)
            .env("P2POOL_ELECTRUM_URL", url)
            .status()?;
        Ok(ExitCode::from(
            status.code().unwrap_or(1).try_into().unwrap_or(1),
        ))
    } else {
        serve(listener)?;
        Ok(ExitCode::SUCCESS)
    }
}

fn serve(listener: TcpListener) -> io::Result<()> {
    for connection in listener.incoming() {
        let stream = connection?;
        thread::spawn(move || {
            if let Err(error) = serve_connection(stream) {
                eprintln!("Electrum mock connection: {error}");
            }
        });
    }
    Ok(())
}

fn serve_connection(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();

    while reader
        .by_ref()
        .take(MAX_REQUEST_BYTES + 1)
        .read_line(&mut line)?
        != 0
    {
        if line.len() as u64 > MAX_REQUEST_BYTES || !line.ends_with('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request exceeds limit or lacks newline",
            ));
        }
        let response = dispatch(&line);
        writeln!(stream, "{response}")?;
        line.clear();
    }
    Ok(())
}

fn dispatch(line: &str) -> Value {
    let value = match serde_json::from_str::<Value>(line) {
        Ok(value) => value,
        Err(_) => return rpc_error(Value::Null, -32700, "parse error"),
    };
    match serde_json::from_value::<Requests>(value) {
        Ok(Requests::Single(request)) => respond(request),
        Ok(Requests::Batch(requests)) => Value::Array(requests.into_iter().map(respond).collect()),
        Err(_) => rpc_error(Value::Null, -32600, "invalid request"),
    }
}

fn respond(request: Request) -> Value {
    let result = match request.method.as_str() {
        "server.version" => version_response(request.params),
        "server.features" => Ok(json!({
            "genesis_hash": GENESIS_HASH,
            "hosts": {},
            "protocol_min": PROTOCOL_VERSION,
            "protocol_max": PROTOCOL_VERSION,
            "pruning": null,
            "server_version": SERVER_NAME,
            "hash_function": "sha256",
            "p2pool": {
                "network": "signet",
                "payout_depth": 127008,
                "coinbase_maturity": 6048,
                "prune_depth": 254016
            }
        })),
        "server.ping" => Ok(Value::Null),
        _ => Err((-32601, "method not found".to_owned())),
    };
    match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": request.id, "result": result}),
        Err((code, message)) => rpc_error(request.id, code, &message),
    }
}

fn version_response(parameters: Value) -> Result<Value, (i32, String)> {
    let (client_name, requested): (String, VersionRequest) =
        serde_json::from_value(parameters).map_err(|_| (-32602, "invalid params".to_owned()))?;
    let (minimum, maximum) = match &requested {
        VersionRequest::Single(exact) => (exact, exact),
        VersionRequest::MinMax(minimum, maximum) => (minimum, maximum),
    };
    let supported = parse_version(PROTOCOL_VERSION);
    let compatible = parse_version(minimum)
        .zip(parse_version(maximum))
        .zip(supported)
        .is_some_and(|((minimum, maximum), supported)| {
            minimum <= supported && supported <= maximum
        });
    if !compatible {
        return Err((
            1,
            format!("unsupported request {requested:?} by {client_name}"),
        ));
    }
    Ok(json!([SERVER_NAME, PROTOCOL_VERSION]))
}

fn parse_version(version: &str) -> Option<Vec<usize>> {
    version.split('.').map(|part| part.parse().ok()).collect()
}

fn rpc_error(identifier: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}})
}
