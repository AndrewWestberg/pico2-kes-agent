//! Durable public Context evidence; never retain payloads of other response kinds.
use kes_protocol::usb::Kind;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub struct ContextEvidence {
    file: File,
    path: PathBuf,
}

impl ContextEvidence {
    /// Reserve and durably record intent before sending the mutation. Existing files are never replaced.
    pub fn reserve(path: &Path, intent: &Value) -> Result<Self, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot reserve context evidence {}: {e}", path.display()))?;
        let mut evidence = Self {
            file,
            path: path.to_owned(),
        };
        evidence.event(intent)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| {
                format!(
                    "cannot sync context evidence directory {}: {e}",
                    path.display()
                )
            })?;
        Ok(evidence)
    }

    /// Persist the complete Context payload before attempting decoding; never persist another kind's payload.
    pub fn reply(&mut self, kind: Kind, payload: &[u8]) -> Result<(), String> {
        let raw = if kind == Kind::Context {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut hex = String::with_capacity(payload.len() * 2);
            for &byte in payload {
                hex.push(HEX[usize::from(byte >> 4)] as char);
                hex.push(HEX[usize::from(byte & 15)] as char);
            }
            Some(hex)
        } else {
            None
        };
        self.event(&json!({"event":"reply", "kind":format!("{kind:?}"), "payload_hex":raw}))
    }

    pub fn event(&mut self, value: &Value) -> Result<(), String> {
        serde_json::to_writer(&mut self.file, value)
            .map_err(|e| format!("cannot write context evidence {}: {e}", self.path.display()))?;
        self.file
            .write_all(b"\n")
            .and_then(|()| self.file.sync_all())
            .map_err(|e| format!("cannot sync context evidence {}: {e}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn retains_context_and_errors_without_clobbering_or_leaking_current() {
        let path = std::env::temp_dir().join(format!(
            "qualification-context-{}-{}.jsonl",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut evidence =
            ContextEvidence::reserve(&path, &json!({"event":"intent","sequence":7})).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        evidence.reply(Kind::Context, &[0x12, 0xab]).unwrap();
        evidence
            .event(&json!({"event":"decode_error","error":"invalid"}))
            .unwrap();
        evidence.reply(Kind::Current, b"secret-current").unwrap();
        let retained = fs::read_to_string(&path).unwrap();
        let events: Vec<Value> = retained
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events[1]["payload_hex"], "12ab");
        assert_eq!(events[2]["event"], "decode_error");
        assert_eq!(events[3]["kind"], "Current");
        assert_eq!(events[3]["payload_hex"], Value::Null);
        assert!(!retained.contains("secret-current"));
        assert!(!retained.contains("7365637265742d63757272656e74"));
        assert!(ContextEvidence::reserve(&path, &json!({"event":"other"})).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), retained);
        drop(evidence);
        fs::remove_file(path).unwrap();
    }
}
