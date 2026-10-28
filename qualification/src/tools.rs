use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

type Fields = BTreeMap<String, String>;

// The manifest deliberately uses a small, strictly checked TOML subset: quoted,
// single-line strings and [[tool]] tables. Reject unknown syntax rather than
// silently misinterpreting a changed inventory.
fn manifest(text: &str) -> Result<(u64, usize, Vec<Fields>), String> {
    let mut globals = Fields::new();
    let mut tools: Vec<Fields> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[tool]]" {
            tools.push(Fields::new());
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid manifest line {}", index + 1))?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty()
            || !key.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
            || value.len() < 2
            || !value.starts_with('"')
            || !value.ends_with('"')
            || value[1..value.len() - 1].contains(&['"', '\\'][..])
        {
            return Err(format!("invalid manifest line {}", index + 1));
        }
        let target = if let Some(tool) = tools.last_mut() {
            tool
        } else {
            &mut globals
        };
        if target
            .insert(key.into(), value[1..value.len() - 1].into())
            .is_some()
        {
            return Err(format!("duplicate manifest key {key}"));
        }
    }
    if globals.len() != 3 || globals.get("format").map(String::as_str) != Some("1") {
        return Err("invalid manifest header".into());
    }
    let timeout = globals
        .get("timeout_ms")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| (1..=60_000).contains(v))
        .ok_or("invalid timeout")?;
    let limit = globals
        .get("output_limit")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| (1..=1_048_576).contains(v))
        .ok_or("invalid output limit")?;
    let mut ids = BTreeSet::new();
    if tools.is_empty() {
        return Err("empty inventory".into());
    }
    for tool in &tools {
        let id = field(tool, "id")?;
        field(tool, "role")?;
        field(tool, "version")?;
        if !ids.insert(id) {
            return Err(format!("duplicate tool {id}"));
        }
        let expected: &[&str] = match field(tool, "kind")? {
            "command" => {
                field(tool, "command")?;
                field(tool, "args")?;
                match field(tool, "match")? {
                    "token" | "contains" | "nonempty" => {}
                    _ => return Err(format!("invalid match for {id}")),
                };
                &["id", "role", "kind", "command", "args", "version", "match"]
            }
            "lock" | "manual" => &["id", "role", "kind", "version"],
            _ => return Err(format!("invalid kind for {id}")),
        };
        if tool.len() != expected.len() || tool.keys().any(|key| !expected.contains(&key.as_str()))
        {
            return Err(format!("invalid fields for {id}"));
        }
    }
    Ok((timeout, limit, tools))
}

fn field<'a>(fields: &'a Fields, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing {key}"))
}

fn drain<R: Read + Send + 'static>(
    mut input: R,
    limit: usize,
    exceeded: Arc<AtomicBool>,
    tx: mpsc::Sender<Vec<u8>>,
) {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match input.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let remaining = limit.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&chunk[..n.min(remaining)]);
                    if n > remaining {
                        exceeded.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
        let _ = tx.send(bytes);
    });
}

fn run(tool: &Fields, timeout: Duration, limit: usize) -> (String, String) {
    let mut command = Command::new(&tool["command"]);
    command
        .args(tool["args"].split('|'))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return ("missing".into(), e.to_string()),
        Err(e) => return ("unsupported".into(), e.to_string()),
    };
    let exceeded = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    drain(
        child.stdout.take().unwrap(),
        limit,
        exceeded.clone(),
        tx.clone(),
    );
    drain(child.stderr.take().unwrap(), limit, exceeded.clone(), tx);
    let start = Instant::now();
    let status = loop {
        if exceeded.load(Ordering::Relaxed) || start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return (
                "unsupported".into(),
                if exceeded.load(Ordering::Relaxed) {
                    "output limit exceeded"
                } else {
                    "version check timed out"
                }
                .into(),
            );
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return ("unsupported".into(), e.to_string());
            }
        }
    };
    let mut output = Vec::new();
    for _ in 0..2 {
        match rx.recv_timeout(timeout.saturating_sub(start.elapsed())) {
            Ok(bytes) => {
                output.extend(bytes);
                output.push(b'\n');
            }
            Err(_) => {
                return (
                    "unsupported".into(),
                    "output pipes did not close before timeout".into(),
                );
            }
        }
    }
    if exceeded.load(Ordering::Relaxed) {
        return ("unsupported".into(), "output limit exceeded".into());
    }
    let observed = String::from_utf8_lossy(&output).trim().to_string();
    if !status.success() {
        return ("unsupported".into(), format!("exit {status}: {observed}"));
    }
    let expected = &tool["version"];
    let matches = match tool["match"].as_str() {
        "token" => observed
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
            .any(|part| part == expected),
        "contains" => observed.contains(expected),
        "nonempty" => !observed.is_empty(),
        _ => false,
    };
    (
        if matches { "available" } else { "unsupported" }.into(),
        observed,
    )
}

fn locked_version(text: &str, name: &str, version: &str) -> bool {
    text.split("[[package]]").skip(1).any(|package| {
        let mut found_name = false;
        let mut found_version = false;
        for line in package.lines() {
            let line = line.trim();
            if line == format!("name = \"{name}\"") {
                found_name = true;
            }
            if line == format!("version = \"{version}\"") {
                found_version = true;
            }
        }
        found_name && found_version
    })
}

fn json(value: &str) -> String {
    let mut result = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => result.push_str(&format!("\\u{:04x}", c as u32)),
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

pub fn check() -> Result<bool, String> {
    let text = fs::read_to_string(format!("{ROOT}/qualification/tools.toml"))
        .map_err(|e| format!("reading tools manifest: {e}"))?;
    let (timeout, limit, tools) = manifest(&text)?;
    let lock = fs::read_to_string(format!("{ROOT}/Cargo.lock"))
        .map_err(|e| format!("reading Cargo.lock: {e}"))?;
    let mut all_available = true;
    let mut results = Vec::new();
    for tool in tools {
        let (status, observed) = match tool["kind"].as_str() {
            "command" => run(&tool, Duration::from_millis(timeout), limit),
            "lock" if locked_version(&lock, &tool["id"], &tool["version"]) => (
                "available".into(),
                format!("Cargo.lock resolves {}", tool["version"]),
            ),
            "lock" => (
                "missing".into(),
                "exact package version absent from Cargo.lock".into(),
            ),
            _ => (
                "unsupported".into(),
                "requires separate physical or source-identity evidence".into(),
            ),
        };
        all_available &= status == "available";
        results.push(format!(
            "{{\"id\":{},\"role\":{},\"expected\":{},\"status\":{},\"observed\":{}}}",
            json(&tool["id"]),
            json(&tool["role"]),
            json(&tool["version"]),
            json(&status),
            json(&observed)
        ));
    }
    println!(
        "{{\"inventory_only\":true,\"gate_status\":\"not_assessed\",\"tools\":[{}]}}",
        results.join(",")
    );
    Ok(all_available)
}
