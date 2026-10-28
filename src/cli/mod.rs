pub mod client;
pub mod receipt;

use crate::files::{open_owner_controlled_file, publish_no_clobber};
use kes_core::identity::OperationId;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_INVOCATION: i32 = 2;
pub const EXIT_PERMISSION: i32 = 3;
pub const EXIT_UNAVAILABLE: i32 = 4;
pub const EXIT_REJECTED: i32 = 5;
pub const EXIT_UNCERTAIN: i32 = 6;
pub const EXIT_FAILURE: i32 = 7;

pub fn run(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match execute(args) {
        Ok(result) => {
            if let Some(output) = result.output {
                let _ = writeln!(stdout, "{output}");
            }
            if let Some(diagnostic) = result.diagnostic {
                let _ = writeln!(stderr, "{diagnostic}");
            }
            result.exit
        }
        Err(error) => {
            let _ = writeln!(stderr, "{error}");
            error.exit()
        }
    }
}

struct ResultOutput {
    exit: i32,
    output: Option<String>,
    diagnostic: Option<String>,
}

#[derive(Debug)]
struct CliError {
    message: String,
    class: i32,
}
impl CliError {
    fn invocation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            class: EXIT_INVOCATION,
        }
    }
    fn io(error: io::Error) -> Self {
        let class = match error.kind() {
            io::ErrorKind::PermissionDenied => EXIT_PERMISSION,
            io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotFound
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock => EXIT_UNAVAILABLE,
            _ => EXIT_FAILURE,
        };
        Self {
            message: error.to_string(),
            class,
        }
    }
    const fn exit(&self) -> i32 {
        self.class
    }
}
impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn execute(args: &[String]) -> Result<ResultOutput, CliError> {
    let mut index = 0;
    let mut socket = PathBuf::from("/run/pico2-kes-agent/management.sock");
    let mut machine = false;
    while index < args.len() {
        match args[index].as_str() {
            "--socket" => {
                index += 1;
                socket = PathBuf::from(
                    args.get(index)
                        .ok_or_else(|| CliError::invocation("--socket requires PATH"))?,
                );
                index += 1;
            }
            "--json" => {
                machine = true;
                index += 1;
            }
            _ => break,
        }
    }
    let command = args
        .get(index)
        .ok_or_else(|| CliError::invocation("missing command"))?;
    index += 1;
    let subcommand = match command.as_str() {
        "status" => None,
        "device" | "pool" | "key" | "certificate" | "recipient" | "operation" => {
            let sub = args
                .get(index)
                .ok_or_else(|| CliError::invocation("missing subcommand"))?;
            index += 1;
            Some(sub.as_str())
        }
        _ => return Err(CliError::invocation("unsupported command")),
    };
    let options = parse_options(&args[index..])?;
    if command == "operation" && subcommand == Some("reconcile") {
        let receipt_path = PathBuf::from(required(&options, "receipt")?);
        let saved = receipt::load(&receipt_path).map_err(CliError::io)?;
        if saved
            .response
            .as_ref()
            .and_then(find_request_digest)
            .is_none()
        {
            return retry_saved_request(&socket, machine, &options, &receipt_path, saved.request);
        }
    }
    let specification = command_spec(command, subcommand, &options)?;
    let request_id = random_id()?;
    let mut request = json!({
        "version": 1,
        "request_id": request_id.to_string(),
        "action": specification.action,
        "arguments": specification.arguments,
    });
    let receipt_path = if specification.mutation {
        let operation_id = options
            .get("operation-id")
            .map(|value| {
                OperationId::parse_hex(value)
                    .map_err(|_| CliError::invocation("invalid --operation-id"))
            })
            .transpose()?
            .unwrap_or(random_id()?);
        let revision = required(&options, "expected-revision")?
            .parse::<u64>()
            .map_err(|_| CliError::invocation("invalid --expected-revision"))?;
        request["operation_id"] = Value::String(operation_id.to_string());
        request["expected_revision"] = Value::from(revision);
        let path = PathBuf::from(required(&options, "receipt")?);
        receipt::create(&path, request.clone()).map_err(CliError::io)?;
        Some(path)
    } else {
        None
    };

    let bytes =
        serde_json::to_vec(&request).map_err(|error| CliError::invocation(error.to_string()))?;
    let response_bytes = match client::request(&socket, &bytes) {
        Ok(response) => response,
        Err(error) => {
            if let Some(path) = &receipt_path {
                let advice = format!(
                    "outcome uncertain; retain {} and run: pico2-kes-agent-cli operation reconcile --receipt {}",
                    path.display(),
                    path.display()
                );
                return Ok(ResultOutput {
                    exit: EXIT_UNCERTAIN,
                    output: None,
                    diagnostic: Some(advice),
                });
            }
            return Err(CliError::io(error));
        }
    };
    let response: Value = serde_json::from_slice(&response_bytes)
        .map_err(|_| CliError::invocation("daemon returned invalid JSON"))?;
    if let Some(path) = &receipt_path {
        receipt::update(path, response.clone()).map_err(CliError::io)?;
    }
    let (exit, human) = classify_response(&response, receipt_path.as_deref());
    if exit == EXIT_SUCCESS {
        write_requested_output(&specification, &options, &response)?;
    }
    let (output, diagnostic) = if machine {
        (
            Some(
                serde_json::to_string(&response)
                    .map_err(|error| CliError::invocation(error.to_string()))?,
            ),
            (exit == EXIT_UNCERTAIN).then_some(human),
        )
    } else if exit == EXIT_SUCCESS {
        (Some(human), None)
    } else {
        (None, Some(human))
    };
    Ok(ResultOutput {
        exit,
        output,
        diagnostic,
    })
}

fn retry_saved_request(
    socket: &Path,
    machine: bool,
    options: &HashMap<String, String>,
    receipt_path: &Path,
    request: Value,
) -> Result<ResultOutput, CliError> {
    let bytes =
        serde_json::to_vec(&request).map_err(|error| CliError::invocation(error.to_string()))?;
    let response_bytes = match client::request(socket, &bytes) {
        Ok(response) => response,
        Err(_) => {
            return Ok(ResultOutput {
                exit: EXIT_UNCERTAIN,
                output: None,
                diagnostic: Some(format!(
                    "outcome still uncertain; retain {} and retry the same reconciliation command",
                    receipt_path.display()
                )),
            });
        }
    };
    let response: Value = serde_json::from_slice(&response_bytes)
        .map_err(|_| CliError::invocation("daemon returned invalid JSON"))?;
    receipt::update(receipt_path, response.clone()).map_err(CliError::io)?;
    let (exit, human) = classify_response(&response, Some(receipt_path));
    if exit == EXIT_SUCCESS
        && request.get("action").and_then(Value::as_str) == Some("device.commission")
    {
        write_requested_output(
            &CommandSpec {
                action: "operation.reconcile",
                arguments: json!({}),
                mutation: false,
                output: Output::Commission,
            },
            options,
            &response,
        )?;
    }
    let (output, diagnostic) = if machine {
        (
            Some(
                serde_json::to_string(&response)
                    .map_err(|error| CliError::invocation(error.to_string()))?,
            ),
            (exit == EXIT_UNCERTAIN).then_some(human),
        )
    } else if exit == EXIT_SUCCESS {
        (Some(human), None)
    } else {
        (None, Some(human))
    };
    Ok(ResultOutput {
        exit,
        output,
        diagnostic,
    })
}

struct CommandSpec {
    action: &'static str,
    arguments: Value,
    mutation: bool,
    output: Output,
}
#[derive(Clone, Copy)]
enum Output {
    None,
    Commission,
    VerificationKey,
    Artifact,
}

fn command_spec(
    command: &str,
    subcommand: Option<&str>,
    options: &HashMap<String, String>,
) -> Result<CommandSpec, CliError> {
    let pool_target = || -> Result<Value, CliError> {
        Ok(json!({
            "pool_id": required(options, "pool")?,
            "incarnation_id": required(options, "incarnation")?,
        }))
    };
    let generation_target = || -> Result<Value, CliError> {
        let mut value = pool_target()?;
        value["generation_id"] = Value::String(required(options, "generation")?.to_owned());
        Ok(value)
    };
    Ok(match (command, subcommand) {
        ("status", None) => CommandSpec {
            action: "device.status",
            arguments: json!({}),
            mutation: false,
            output: Output::None,
        },
        ("device", Some("commission")) => CommandSpec {
            action: "device.commission",
            arguments: json!({ "usb_serial": required(options, "usb-serial")? }),
            mutation: true,
            output: Output::Commission,
        },
        ("pool", Some("list")) => CommandSpec {
            action: "pool.list",
            arguments: json!({}),
            mutation: false,
            output: Output::None,
        },
        ("pool", Some("status")) => CommandSpec {
            action: "pool.status",
            arguments: json!({ "pool_id": required(options, "pool")? }),
            mutation: false,
            output: Output::None,
        },
        ("pool", Some("enroll")) => CommandSpec {
            action: "pool.enroll",
            arguments: json!({
                "cold_verification_key": public_hex_file(Path::new(required(options, "cold-vkey")?), 32)?,
                "network": required(options, "network")?,
            }),
            mutation: true,
            output: Output::None,
        },
        ("pool", Some("delete")) => {
            require_confirmation(options)?;
            CommandSpec {
                action: "pool.delete",
                arguments: pool_target()?,
                mutation: true,
                output: Output::None,
            }
        }
        ("key", Some("generate")) => CommandSpec {
            action: "generation.create",
            arguments: pool_target()?,
            mutation: true,
            output: Output::None,
        },
        ("key", Some("verification-key")) => CommandSpec {
            action: "generation.public_key",
            arguments: generation_target()?,
            mutation: false,
            output: Output::VerificationKey,
        },
        ("key", Some("export")) => CommandSpec {
            action: "generation.artifact",
            arguments: generation_target()?,
            mutation: false,
            output: Output::Artifact,
        },
        ("key", Some("discard")) => {
            require_confirmation(options)?;
            CommandSpec {
                action: "generation.discard",
                arguments: generation_target()?,
                mutation: true,
                output: Output::None,
            }
        }
        ("certificate", Some("install")) => CommandSpec {
            action: "generation.certificate",
            arguments: {
                let mut value = generation_target()?;
                value["certificate"] = Value::String(public_hex_file(
                    Path::new(required(options, "certificate")?),
                    4096,
                )?);
                value
            },
            mutation: true,
            output: Output::None,
        },
        ("recipient", Some("set")) => CommandSpec {
            action: "recipient.set",
            arguments: json!({ "public_key": public_hex_file(Path::new(required(options, "public-key")?), 32)? }),
            mutation: true,
            output: Output::None,
        },
        ("operation", Some("reconcile")) => {
            let saved =
                receipt::load(Path::new(required(options, "receipt")?)).map_err(CliError::io)?;
            let operation_id = saved
                .request
                .get("operation_id")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::invocation("receipt has no operation_id"))?;
            let digest = saved
                .response
                .as_ref()
                .and_then(find_request_digest)
                .ok_or_else(|| {
                    CliError::invocation(
                        "receipt has no device request digest; retry after daemon recovery",
                    )
                })?;
            CommandSpec {
                action: "operation.reconcile",
                arguments: json!({ "operation_id": operation_id, "request_digest": digest }),
                mutation: false,
                output: Output::Commission,
            }
        }
        _ => return Err(CliError::invocation("unsupported command")),
    })
}

fn parse_options(args: &[String]) -> Result<HashMap<String, String>, CliError> {
    let mut options = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let name = args[index]
            .strip_prefix("--")
            .ok_or_else(|| CliError::invocation("expected --option"))?;
        if matches!(name, "yes") {
            if options.insert(name.to_owned(), String::new()).is_some() {
                return Err(CliError::invocation("duplicate option"));
            }
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| CliError::invocation(format!("--{name} requires a value")))?;
        if options.insert(name.to_owned(), value.clone()).is_some() {
            return Err(CliError::invocation("duplicate option"));
        }
        index += 2;
    }
    Ok(options)
}

fn require_confirmation(options: &HashMap<String, String>) -> Result<(), CliError> {
    if options.contains_key("yes") {
        Ok(())
    } else {
        Err(CliError::invocation(
            "destructive command requires confirmation; review the target and retention warning, then pass --yes",
        ))
    }
}

fn required<'a>(options: &'a HashMap<String, String>, name: &str) -> Result<&'a str, CliError> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| CliError::invocation(format!("missing --{name}")))
}

fn random_id() -> Result<OperationId, CliError> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(CliError::io)?;
    Ok(OperationId::from_bytes(bytes))
}

fn public_hex_file(path: &Path, max_bytes: usize) -> Result<String, CliError> {
    let mut file = open_owner_controlled_file(path).map_err(CliError::io)?;
    if file.metadata().map_err(CliError::io)?.len() > 16 * 1024 {
        return Err(CliError::invocation("public input file exceeds 16 KiB"));
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(CliError::io)?;
    let value = if text.trim_start().starts_with('{') {
        let json: Value = serde_json::from_str(&text)
            .map_err(|_| CliError::invocation("invalid public envelope"))?;
        json.get("cborHex")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::invocation("public envelope has no cborHex"))?
            .to_owned()
    } else {
        text.trim().to_owned()
    };
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() / 2 > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::invocation(
            "invalid lowercase hexadecimal public input",
        ));
    }
    Ok(value)
}

fn write_requested_output(
    specification: &CommandSpec,
    options: &HashMap<String, String>,
    response: &Value,
) -> Result<(), CliError> {
    let Some(path) = options.get("out") else {
        return Ok(());
    };
    let bytes = match specification.output {
        Output::None => {
            return Err(CliError::invocation(
                "--out is not supported by this command",
            ));
        }
        Output::Commission => {
            let result = response
                .get("result")
                .filter(|result| result.get("kind").and_then(Value::as_str) == Some("commissioned"))
                .ok_or_else(|| {
                    CliError::invocation("response has no commissioned device record")
                })?;
            serde_json::to_vec_pretty(result)
                .map_err(|error| CliError::invocation(error.to_string()))?
        }
        Output::VerificationKey => {
            let key = find_field(response, "verification_key")
                .ok_or_else(|| CliError::invocation("response has no verification key"))?;
            serde_json::to_vec_pretty(&json!({
                "type": "KesVerificationKey_ed25519_kes_2^6",
                "description": "Pico2 KES agent verification key",
                "cborHex": format!("5820{key}"),
            }))
            .map_err(|error| CliError::invocation(error.to_string()))?
        }
        Output::Artifact => decode_hex(
            find_field(response, "artifact")
                .ok_or_else(|| CliError::invocation("artifact is retired or unavailable"))?,
        )?,
    };
    publish_no_clobber(Path::new(path), &bytes, 0o600).map_err(CliError::io)
}

fn classify_response(response: &Value, receipt: Option<&Path>) -> (i32, String) {
    let outcome = response
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("uncertain");
    match outcome {
        "success" => {
            if find_field(response, "state") == Some("rejected") {
                return (EXIT_REJECTED, response.to_string());
            }
            (EXIT_SUCCESS, response.to_string())
        }
        "rejected" => (EXIT_REJECTED, response.to_string()),
        "pending" | "uncertain" => (
            EXIT_UNCERTAIN,
            receipt.map_or_else(
                || response.to_string(),
                |path| format!(
                    "outcome uncertain; retain {} and run: pico2-kes-agent-cli operation reconcile --receipt {}",
                    path.display(), path.display()
                ),
            ),
        ),
        _ => (EXIT_FAILURE, response.to_string()),
    }
}

fn find_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    match value {
        Value::Object(object) => object
            .get(field)
            .and_then(Value::as_str)
            .or_else(|| object.values().find_map(|value| find_field(value, field))),
        Value::Array(values) => values.iter().find_map(|value| find_field(value, field)),
        _ => None,
    }
}
fn find_request_digest(value: &Value) -> Option<&str> {
    find_field(value, "request_digest")
}
fn decode_hex(value: &str) -> Result<Vec<u8>, CliError> {
    if !value.len().is_multiple_of(2) {
        return Err(CliError::invocation("invalid artifact hex"));
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let nibble = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            Ok(
                (nibble(pair[0]).ok_or_else(|| CliError::invocation("invalid artifact hex"))? << 4)
                    | nibble(pair[1])
                        .ok_or_else(|| CliError::invocation("invalid artifact hex"))?,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{fs::PermissionsExt, net::UnixListener},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn status_runs_through_the_real_framed_unix_client() {
        let directory = std::env::temp_dir().join(format!(
            "pico2-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("management.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).unwrap();
            let request: Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request["action"], "device.status");
            let response = serde_json::to_vec(&json!({
                "version": 1,
                "request_id": request["request_id"],
                "outcome": "success",
                "result": { "health": "ready" },
                "error": Value::Null,
            }))
            .unwrap();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            &[
                "--socket".to_owned(),
                socket.display().to_string(),
                "--json".to_owned(),
                "status".to_owned(),
            ],
            &mut stdout,
            &mut stderr,
        );
        server.join().unwrap();
        assert_eq!(exit, EXIT_SUCCESS);
        assert!(stderr.is_empty());
        let response: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(response["result"]["health"], "ready");
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn reconciliation_resends_saved_mutation_when_no_device_digest_was_received() {
        let directory = std::env::temp_dir().join(format!(
            "pico2-cli-reconcile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("management.sock");
        let receipt_path = directory.join("operation.json");
        let request = json!({
            "version": 1,
            "request_id": "00112233445566778899aabbccddeeff",
            "action": "recipient.set",
            "arguments": { "public_key": "11".repeat(32) },
            "operation_id": "ffeeddccbbaa99887766554433221100",
            "expected_revision": 1,
        });
        receipt::create(&receipt_path, request.clone()).unwrap();

        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut bytes).unwrap();
            let retried: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(retried, request);
            let response = serde_json::to_vec(&json!({
                "version": 1,
                "request_id": retried["request_id"],
                "outcome": "success",
                "result": { "kind": "applied", "revision": 2 },
                "error": Value::Null,
            }))
            .unwrap();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            &[
                "--socket".to_owned(),
                socket.display().to_string(),
                "--json".to_owned(),
                "operation".to_owned(),
                "reconcile".to_owned(),
                "--receipt".to_owned(),
                receipt_path.display().to_string(),
            ],
            &mut stdout,
            &mut stderr,
        );
        server.join().unwrap();
        assert_eq!(exit, EXIT_SUCCESS);
        assert!(stderr.is_empty());
        assert_eq!(
            receipt::load(&receipt_path).unwrap().response.unwrap()["result"]["revision"],
            2
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
