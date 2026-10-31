use crate::evidence;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const IMAGE_LIMIT: u64 = 1_048_576;
const STATIC_RAM_LIMIT: u64 = 128 * 1_024;
const FLASH_BYTES: u64 = 4 * 1024 * 1024;
const PRODUCTION_VID: &str = "1209";
const PRODUCTION_PID: &str = "4b45";

pub fn run(arguments: &[String]) -> i32 {
    if !arguments.is_empty() {
        eprintln!("usage: qualification hardware");
        return 2;
    }
    match execute() {
        Ok((path, passed)) => {
            println!("{}", path.display());
            if passed { 0 } else { 1 }
        }
        Err(error) => {
            eprintln!("hardware qualification: {error}");
            1
        }
    }
}

fn execute() -> Result<(PathBuf, bool), String> {
    let repository = Path::new(ROOT)
        .parent()
        .ok_or("repository path unavailable")?;
    let (revision, dirty) = evidence::candidate().ok_or("candidate identity unavailable")?;
    let status = Command::new("cargo")
        .args([
            "build",
            "--offline",
            "--release",
            "-p",
            "pico2-kes-firmware",
            "--target",
            "thumbv8m.main-none-eabihf",
        ])
        .current_dir(repository)
        .status()
        .map_err(|error| format!("cannot run firmware build: {error}"))?;
    if !status.success() {
        return Err("firmware release build failed".to_owned());
    }

    let elf = repository.join("target/thumbv8m.main-none-eabihf/release/pico2-kes-firmware");
    let size = measure_size(&elf)?;
    let image_bytes = size
        .text
        .checked_add(size.data)
        .ok_or("image-size overflow")?;
    let static_ram_bytes = size.data.checked_add(size.bss).ok_or("RAM-size overflow")?;
    let firmware_sha256 = file_digest(&elf)?;

    let evidence_directory = repository
        .join("evidence")
        .join(format!("{revision}-{dirty}"))
        .join("hardware");
    let flash_path = evidence_directory.join("flash-identity.json");
    let usb_path = evidence_directory.join("production-usb.json");
    let flash = read_json(&flash_path)?;
    let usb = read_json(&usb_path)?;
    let bundle = usb
        .pointer("/firmware/bundle")
        .and_then(Value::as_str)
        .ok_or("signed release bundle path is missing")?;
    let (verified, manifest) = evidence::command(
        "python3",
        &["tools/firmware.py", "verify", "--bundle", bundle],
        Duration::from_secs(60),
    )
    .ok_or("signed release verification unavailable")?;
    if !verified {
        return Err("signed release verification failed".into());
    }
    let manifest: Value =
        serde_json::from_slice(&manifest).map_err(|_| "invalid verified release manifest")?;
    let flash_ok = flash_observation_passes(&flash);
    let usb_ok = usb_observation_passes(&usb, &firmware_sha256, &revision, &manifest);
    let definition_approved = evidence::approved_definition();
    let passed = definition_approved
        && image_bytes <= IMAGE_LIMIT
        && static_ram_bytes <= STATIC_RAM_LIMIT
        && flash_ok
        && usb_ok;

    let report = json!({
        "schema_version": 3,
        "candidate": {"revision": revision, "dirty_sha256": dirty},
        "gate": {
            "name": "hardware",
            "definition_sha256": evidence::APPROVED_DIGEST,
            "definition_approved": definition_approved,
            "scope": "Pico2 A2 production firmware boots and communicates on the observed fitted device"
        },
        "command": "cargo run --locked -p qualification -- hardware",
        "measurements": {
            "firmware": {
                "elf": elf,
                "sha256": firmware_sha256,
                "signed_bundle": bundle,
                "signed_uf2_sha256": usb.pointer("/firmware/signed_uf2_sha256"),
                "source_commit": manifest.get("commit"),
                "text_bytes": size.text,
                "data_bytes": size.data,
                "bss_bytes": size.bss,
                "image_bytes": image_bytes,
                "image_limit_bytes": IMAGE_LIMIT,
                "static_ram_bytes": static_ram_bytes,
                "static_ram_limit_bytes": STATIC_RAM_LIMIT
            },
            "fitted_flash": {
                "evidence": flash_path,
                "passes": flash_ok,
                "jedec_id": flash.pointer("/decoded/jedec_id_hex"),
                "sfdp_header": flash.pointer("/decoded/sfdp_header_hex"),
                "capacity_bytes": flash.pointer("/decoded/density_bytes")
            },
            "production_usb": {
                "evidence": usb_path,
                "passes": usb_ok,
                "vendor_id": usb.pointer("/usb/vendor_id"),
                "product_id": usb.pointer("/usb/product_id"),
                "serial": usb.pointer("/usb/serial"),
                "health": usb.pointer("/startup/health")
            }
        },
        "checks": [
            {"name":"firmware image fits reserved image region", "passed": image_bytes <= IMAGE_LIMIT},
            {"name":"linked static RAM fits owned budget", "passed": static_ram_bytes <= STATIC_RAM_LIMIT},
            {"name":"fitted JEDEC/SFDP identity matches supported 4 MiB flash", "passed": flash_ok},
            {"name":"verified signed candidate was transferred and reached pinned ready production USB", "passed": usb_ok}
        ],
        "exclusions": [
            "Locked MSD does not expose flash readback; firmware execution is operationally inferred, not independently attested.",
            "No voltage, temperature, lifetime, or per-sector endurance claim is made.",
            "Operational erase verification covers software behavior; it is not a physical anti-extraction guarantee.",
            "Physical extraction, invasive remanence, malicious replacement firmware, captured-storage rollback, and recipient-retained backups remain outside the threat boundary."
        ],
        "verdict": if passed { "pass" } else { "fail" }
    });
    let path = evidence_directory.join("report.json");
    let bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    evidence::atomic_write(&path, &bytes).map_err(|error| error.to_string())?;
    Ok((path, passed))
}

fn flash_observation_passes(value: &Value) -> bool {
    value
        .pointer("/decoded/jedec_id_hex")
        .and_then(Value::as_str)
        == Some("ef4016")
        && value
            .pointer("/decoded/sfdp_header_hex")
            .and_then(Value::as_str)
            == Some("534644500a0100ff00080117800000ff")
        && value
            .pointer("/decoded/density_bytes")
            .and_then(Value::as_u64)
            == Some(FLASH_BYTES)
        && value
            .pointer("/decoded/matched_firmware_allowlist")
            .and_then(Value::as_bool)
            == Some(true)
}

fn usb_observation_passes(
    value: &Value,
    firmware_sha256: &str,
    revision: &str,
    manifest: &Value,
) -> bool {
    let Some(image) = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry.get("name").and_then(Value::as_str) == Some("pico2-kes-firmware.signed.uf2")
            })
        })
        .and_then(|entry| entry.get("sha256"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    value.pointer("/firmware/sha256").and_then(Value::as_str) == Some(firmware_sha256)
        && manifest.get("commit").and_then(Value::as_str) == Some(revision)
        && value
            .pointer("/firmware/signed_uf2_sha256")
            .and_then(Value::as_str)
            == Some(image)
        && value
            .pointer("/firmware/transfer_method")
            .and_then(Value::as_str)
            == Some("signed-msd")
        && value
            .pointer("/firmware/transfer_flushed")
            .and_then(Value::as_bool)
            == Some(true)
        && value
            .pointer("/startup/identity_authenticated")
            .and_then(Value::as_bool)
            == Some(true)
        && value.pointer("/usb/vendor_id").and_then(Value::as_str) == Some(PRODUCTION_VID)
        && value.pointer("/usb/product_id").and_then(Value::as_str) == Some(PRODUCTION_PID)
        && value
            .pointer("/usb/serial")
            .and_then(Value::as_str)
            .is_some_and(|serial| serial.len() == 16)
        && value.pointer("/startup/health").and_then(Value::as_str) == Some("ready")
        && value.pointer("/result").and_then(Value::as_str) == Some("pass")
}

fn read_json(path: &Path) -> Result<Value, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024 {
        return Err(format!(
            "{} must be a regular non-symlink file <=1 MiB",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid {}: {error}", path.display()))
}

fn file_digest(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(Clone, Copy)]
struct Size {
    text: u64,
    data: u64,
    bss: u64,
}

fn measure_size(elf: &Path) -> Result<Size, String> {
    let output = Command::new("size")
        .arg(elf)
        .output()
        .map_err(|error| format!("cannot execute size: {error}"))?;
    if !output.status.success() {
        return Err("size rejected firmware ELF".to_owned());
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| "size output is not UTF-8")?;
    let row = stdout.lines().nth(1).ok_or("size output has no data row")?;
    let mut columns = row.split_whitespace();
    let text = columns
        .next()
        .ok_or("size text missing")?
        .parse()
        .map_err(|_| "invalid text size")?;
    let data = columns
        .next()
        .ok_or("size data missing")?
        .parse()
        .map_err(|_| "invalid data size")?;
    let bss = columns
        .next()
        .ok_or("size bss missing")?
        .parse()
        .map_err(|_| "invalid bss size")?;
    Ok(Size { text, data, bss })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observations_require_exact_supported_identity_and_ready_production_firmware() {
        let flash = json!({"decoded": {
            "jedec_id_hex":"ef4016",
            "sfdp_header_hex":"534644500a0100ff00080117800000ff",
            "density_bytes": FLASH_BYTES,
            "matched_firmware_allowlist": true
        }});
        let usb = json!({
            "firmware":{"sha256":"abc", "signed_uf2_sha256":"signed", "transfer_method":"signed-msd", "transfer_flushed":true},
            "usb":{"vendor_id":PRODUCTION_VID,"product_id":PRODUCTION_PID,"serial":"0011223344556677"},
            "startup":{"health":"ready", "identity_authenticated":true},
            "result":"pass"
        });
        let manifest = json!({"commit":"candidate","artifacts":[
            {"name":"pico2-kes-firmware.signed.uf2","sha256":"signed"}
        ]});
        assert!(flash_observation_passes(&flash));
        assert!(usb_observation_passes(&usb, "abc", "candidate", &manifest));
        assert!(!usb_observation_passes(&usb, "def", "candidate", &manifest));
        assert!(!usb_observation_passes(&usb, "abc", "another", &manifest));
        for (pointer, wrong) in [
            ("/firmware/signed_uf2_sha256", json!("another")),
            ("/firmware/transfer_flushed", json!(false)),
            ("/startup/identity_authenticated", json!(false)),
            ("/startup/health", json!("unavailable")),
        ] {
            let mut changed = usb.clone();
            *changed.pointer_mut(pointer).unwrap() = wrong;
            assert!(!usb_observation_passes(
                &changed,
                "abc",
                "candidate",
                &manifest
            ));
        }
    }
}
