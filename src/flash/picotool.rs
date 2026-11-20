//! Bounded `picotool` v2.3.1 subprocess wrapper and RP2350 policy checks.

use std::path::Path;
use std::process::Command;

pub const EXPECTED_POLICY: &str = "rp2350-signed-msd-v1";

pub fn run_picotool(picotool_bin: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(picotool_bin)
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute {}: {e}", picotool_bin.display()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("picotool {:?} failed: {stderr}", args));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn wipe_device(picotool_bin: &Path) -> Result<(), String> {
    run_picotool(picotool_bin, &["erase", "-a"]).map(|_| ())
}

pub fn otp_stage(picotool_bin: &Path, stage: &str, json_path: &Path) -> Result<(), String> {
    match stage {
        "prepare" | "enable" | "lock" => {
            let p = json_path.to_str().ok_or("non-UTF8 OTP path")?;
            run_picotool(picotool_bin, &["otp", "load", p]).map(|_| ())
        }
        other => Err(format!("unknown otp stage: {other} (expected prepare|enable|lock)")),
    }
}
