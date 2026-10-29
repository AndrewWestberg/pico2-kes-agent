pub mod client;
pub mod receipt;
pub mod status;

use crate::{
    backup::{recipient, recover},
    files::{open_owner_controlled_file, publish_no_clobber},
};
use kes_core::identity::OperationId;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_INVOCATION: i32 = 2;
pub const EXIT_PERMISSION: i32 = 3;
pub const EXIT_UNAVAILABLE: i32 = 4;
pub const EXIT_REJECTED: i32 = 5;
pub const EXIT_UNCERTAIN: i32 = 6;
pub const EXIT_FAILURE: i32 = 7;

const USAGE: &str = "\
pico2-kes-agent-cli [--socket PATH] [--json] COMMAND

Commands:
  status
  device commission
  pool list|status|enroll|delete
  key generate|verification-key|export|discard
  certificate install
  recipient create|set
  operation reconcile
  restore

Run service commands through the daemon management socket. No direct USB mode exists.";

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
    fn failure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            class: EXIT_FAILURE,
        }
    }
    fn backup(message: impl Into<String>) -> Self {
        Self::failure(message)
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
    if matches!(args, [argument] if matches!(argument.as_str(), "--help" | "-h" | "help")) {
        return Ok(ResultOutput {
            exit: EXIT_SUCCESS,
            output: Some(USAGE.to_owned()),
            diagnostic: None,
        });
    }
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
        "status" | "restore" => None,
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
    validate_options(command, subcommand, &options)?;
    if command == "recipient" && subcommand == Some("create") {
        return create_recipient(&options, machine);
    }
    if command == "restore" {
        return restore_backup(&options, machine);
    }
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
            if let Some(path) = &receipt_path
                && error.outcome_uncertain()
            {
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
            return Err(CliError::io(error.into_io()));
        }
    };
    let response: Value = serde_json::from_slice(&response_bytes)
        .map_err(|_| CliError::failure("daemon returned invalid JSON"))?;
    if let Some(path) = &receipt_path {
        receipt::update(path, response.clone()).map_err(CliError::io)?;
    }
    let (exit, mut human) = classify_response(&response, receipt_path.as_deref());
    if exit == EXIT_SUCCESS
        && matches!(specification.action, "device.status" | "pool.status")
        && let Some(status) = status::human(&response)
    {
        human = status;
    }
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

fn create_recipient(
    options: &HashMap<String, String>,
    machine: bool,
) -> Result<ResultOutput, CliError> {
    let private_path = Path::new(required(options, "out")?);
    let public_path = Path::new(required(options, "public-out")?);
    if std::fs::symlink_metadata(private_path).is_ok()
        || std::fs::symlink_metadata(public_path).is_ok()
    {
        return Err(CliError::backup("recipient output already exists"));
    }
    let (public, private) = recipient::create_interactive()
        .map_err(|_| CliError::backup("recipient creation failed"))?;
    let public_bytes = public
        .json()
        .map_err(|_| CliError::backup("recipient public encoding failed"))?;
    publish_no_clobber(public_path, &public_bytes, 0o600).map_err(CliError::io)?;
    if let Err(error) = publish_no_clobber(private_path, private.encoded(), 0o600) {
        let _ = std::fs::remove_file(public_path);
        return Err(CliError::io(error));
    }
    Ok(ResultOutput {
        exit: EXIT_SUCCESS,
        output: Some(if machine {
            json!({
                "outcome": "success",
                "recipient_key": private_path,
                "public_key": public_path,
                "recipient_id": public.recipient_id_hex(),
            })
            .to_string()
        } else {
            format!(
                "created protected recipient {} and public recipient {}",
                private_path.display(),
                public_path.display()
            )
        }),
        diagnostic: None,
    })
}

fn restore_backup(
    options: &HashMap<String, String>,
    machine: bool,
) -> Result<ResultOutput, CliError> {
    let expected_device = recover::decode_hex::<16>(required(options, "device")?)
        .ok_or_else(|| CliError::invocation("invalid --device"))?;
    let expected = recover::Expectations {
        device: expected_device,
        pool: recover::decode_hex(required(options, "pool")?)
            .ok_or_else(|| CliError::invocation("invalid --pool"))?,
        incarnation: recover::decode_hex(required(options, "incarnation")?)
            .ok_or_else(|| CliError::invocation("invalid --incarnation"))?,
        generation: recover::decode_hex(required(options, "generation")?)
            .ok_or_else(|| CliError::invocation("invalid --generation"))?,
        verification_key: recover::parse_verification_key_file(Path::new(required(
            options,
            "verification-key",
        )?))
        .map_err(|_| CliError::backup("invalid verification-key file"))?,
        identity_public_key: recover::load_identity(
            Path::new(required(options, "device-identity")?),
            expected_device,
        )
        .map_err(|_| CliError::backup("invalid device identity or binding"))?,
    };
    let artifact = recover::read_file(
        Path::new(required(options, "artifact")?),
        false,
        kes_core::backup::MAX_BACKUP_BYTES as u64,
    )
    .map_err(|_| CliError::backup("invalid backup artifact input"))?;
    let recipient_bytes =
        recover::read_file(Path::new(required(options, "recipient-key")?), true, 16_384)
            .map_err(|_| CliError::backup("invalid recipient-key input"))?;
    let recipient = recipient::RecipientKeyFile::parse(recipient_bytes)
        .map_err(|_| CliError::backup("invalid recipient-key format"))?;
    let passphrase = recipient::prompt_existing_passphrase()
        .map_err(|_| CliError::backup("recipient passphrase input failed"))?;
    let output = Path::new(required(options, "out")?);
    recover::restore_to_file(&artifact, &recipient, &passphrase, expected, output)
        .map_err(|_| CliError::backup("backup restoration rejected"))?;
    Ok(ResultOutput {
        exit: EXIT_SUCCESS,
        output: Some(if machine {
            json!({"outcome":"success", "restored_key":output}).to_string()
        } else {
            format!("restored conventional KES signing key {}", output.display())
        }),
        diagnostic: None,
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
        ("pool", Some("list")) => {
            let page_size = options
                .get("page-size")
                .map(|value| {
                    value
                        .parse::<u8>()
                        .ok()
                        .filter(|size| (1..=16).contains(size))
                        .ok_or_else(|| CliError::invocation("--page-size must be 1..=16"))
                })
                .transpose()?
                .unwrap_or(16);
            let mut arguments = json!({"page_size": page_size});
            if let Some(cursor) = options.get("cursor") {
                arguments["cursor"] = Value::String(cursor.clone());
            }
            CommandSpec {
                action: "pool.list",
                arguments,
                mutation: false,
                output: Output::None,
            }
        }
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
            require_confirmation(
                options,
                format!(
                    "deleting pool {} incarnation {} permanently removes all device-side operational keys and retained artifacts for that pool; external copies are unaffected",
                    required(options, "pool")?,
                    required(options, "incarnation")?
                ),
            )?;
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
        ("key", Some("verification-key")) => {
            required(options, "out")?;
            CommandSpec {
                action: "generation.public_key",
                arguments: generation_target()?,
                mutation: false,
                output: Output::VerificationKey,
            }
        }
        ("key", Some("export")) => {
            required(options, "out")?;
            CommandSpec {
                action: "generation.artifact",
                arguments: generation_target()?,
                mutation: false,
                output: Output::Artifact,
            }
        }
        ("key", Some("discard")) => {
            require_confirmation(
                options,
                format!(
                    "discarding staged generation {} permanently ends device-side artifact retrieval for that generation; the active generation and external copies are unaffected",
                    required(options, "generation")?
                ),
            )?;
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
            arguments: json!({ "public_key": recipient_public_hex_file(Path::new(required(options, "public-key")?))? }),
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

fn validate_options(
    command: &str,
    subcommand: Option<&str>,
    options: &HashMap<String, String>,
) -> Result<(), CliError> {
    let allowed: &[&str] = match (command, subcommand) {
        ("status", None) => &[],
        ("device", Some("commission")) => &[
            "usb-serial",
            "operation-id",
            "expected-revision",
            "receipt",
            "out",
        ],
        ("pool", Some("list")) => &["page-size", "cursor"],
        ("pool", Some("status")) => &["pool"],
        ("pool", Some("enroll")) => &[
            "cold-vkey",
            "network",
            "operation-id",
            "expected-revision",
            "receipt",
        ],
        ("pool", Some("delete")) => &[
            "pool",
            "incarnation",
            "operation-id",
            "expected-revision",
            "receipt",
            "yes",
        ],
        ("key", Some("generate")) => &[
            "pool",
            "incarnation",
            "operation-id",
            "expected-revision",
            "receipt",
        ],
        ("key", Some("verification-key" | "export")) => {
            &["pool", "incarnation", "generation", "out"]
        }
        ("key", Some("discard")) => &[
            "pool",
            "incarnation",
            "generation",
            "operation-id",
            "expected-revision",
            "receipt",
            "yes",
        ],
        ("certificate", Some("install")) => &[
            "pool",
            "incarnation",
            "generation",
            "certificate",
            "operation-id",
            "expected-revision",
            "receipt",
        ],
        ("recipient", Some("set")) => {
            &["public-key", "operation-id", "expected-revision", "receipt"]
        }
        ("recipient", Some("create")) => &["out", "public-out"],
        ("operation", Some("reconcile")) => &["receipt", "out"],
        ("restore", None) => &[
            "device",
            "pool",
            "incarnation",
            "generation",
            "verification-key",
            "device-identity",
            "artifact",
            "recipient-key",
            "out",
        ],
        _ => return Err(CliError::invocation("unsupported command")),
    };
    if let Some(option) = options
        .keys()
        .find(|option| !allowed.contains(&option.as_str()))
    {
        return Err(CliError::invocation(format!(
            "unsupported option --{option}"
        )));
    }
    Ok(())
}

fn require_confirmation(
    options: &HashMap<String, String>,
    warning: String,
) -> Result<(), CliError> {
    if options.contains_key("yes") {
        return Ok(());
    }
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            CliError::invocation(format!(
                "{warning}; pass --yes when no interactive terminal is available"
            ))
        })?;
    writeln!(
        terminal,
        "{warning}\nType yes to confirm this exact target:"
    )
    .map_err(CliError::io)?;
    let mut response = String::new();
    BufReader::new(terminal.try_clone().map_err(CliError::io)?)
        .read_line(&mut response)
        .map_err(CliError::io)?;
    if response.trim() == "yes" {
        Ok(())
    } else {
        Err(CliError::invocation("confirmation declined"))
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

fn recipient_public_hex_file(path: &Path) -> Result<String, CliError> {
    let mut file = open_owner_controlled_file(path).map_err(CliError::io)?;
    if file.metadata().map_err(CliError::io)?.len() > 16 * 1024 {
        return Err(CliError::invocation("recipient public file exceeds 16 KiB"));
    }
    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).map_err(CliError::io)?;
    let public = recipient::parse_public_json(&encoded)
        .map_err(|_| CliError::invocation("invalid recipient public file"))?;
    Ok(public.public_key_hex())
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
        let encoded = json
            .get("cborHex")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::invocation("public envelope has no cborHex"))?;
        if max_bytes == 32 && encoded.len() == 68 && encoded.starts_with("5820") {
            encoded[4..].to_owned()
        } else {
            encoded.to_owned()
        }
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
        "rejected" => {
            let code = response
                .pointer("/error/code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let exit = match code {
                "permission_denied" => EXIT_PERMISSION,
                "busy" | "device_unavailable" | "socket_conflict" => EXIT_UNAVAILABLE,
                _ => EXIT_REJECTED,
            };
            (exit, response.to_string())
        }
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

    #[test]
    fn standard_verification_key_envelope_yields_raw_key_bytes() {
        let directory = std::env::temp_dir().join(format!(
            "pico2-cli-vkey-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("cold.vkey");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "type": "StakePoolVerificationKey_ed25519",
                "description": "disposable",
                "cborHex": format!("5820{}", "ab".repeat(32)),
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(public_hex_file(&path, 32).unwrap(), "ab".repeat(32));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
