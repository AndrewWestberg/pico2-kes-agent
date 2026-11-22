use super::*;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

fn payload_mode(path: &str) -> u32 {
    if path.starts_with("bin/") || path == "tools/picotool" {
        0o755
    } else {
        0o644
    }
}

fn distribution() -> Value {
    let tag = "v0.1.0-rc.25";
    let components: Vec<_> = COMPONENTS
        .iter()
        .map(|(name, path)| {
            let version = if *name == "firmware" {
                "v0.1.0-rc.24"
            } else {
                tag
            };
            json!({"name": name, "artifact": path, "version": version})
        })
        .collect();
    let artifacts: Vec<_> = COMPONENTS
        .iter()
        .map(|(_, path)| path)
        .chain(REQUIRED_PAYLOAD)
        .map(|path| {
            json!({
                "path": path,
                "size_bytes": 5,
                "sha256": format!("{:x}", Sha256::digest(b"hello")),
                "class": artifact_class(path),
                "mode": payload_mode(path),
            })
        })
        .collect();
    json!({
        "schema_version": 1,
        "purpose": DISTRIBUTION_PURPOSE,
        "release": {"tag": tag, "version": tag},
        "platform": {"target": "x86_64-unknown-linux-gnu", "glibc_min": "2.36", "systemd": true, "udev": true},
        "compatibility": {"usb_profiles": ["usb-protocol-1"]},
        "qualification": "candidate",
        "components": components,
        "artifacts": artifacts,
    })
}

fn normalize(doc: &Value) -> Result<ReleaseManifest, ReleaseError> {
    normalize_distribution(&serde_json::to_vec(doc).unwrap())
}

#[test]
fn maps_signed_wire_fields_without_rewriting_paths() {
    let mut distribution = distribution();
    let manifest = normalize(&distribution).unwrap();
    assert_eq!(manifest.version, "v0.1.0-rc.25");
    assert_eq!(manifest.firmware_version.as_deref(), Some("v0.1.0-rc.24"));
    assert_eq!(manifest.usb_protocol_major, 1);
    assert_eq!(manifest.artifacts[0].path, "bin/p2kesup");
    assert_eq!(manifest.artifacts[0].mode.as_deref(), Some("0o755"));

    distribution["schema_version"] = json!(2);
    assert!(normalize(&distribution).is_err());
}

#[test]
fn rejects_noncanonical_duplicate_and_reserved_paths() {
    for path in [
        "",
        "./bin/p2kes",
        "bin//p2kes",
        "../etc/passwd",
        "/x",
        "dir\\x",
        "dir/",
    ] {
        assert!(matches!(
            safe_path(path),
            Err(ReleaseError::PathConfinement(_))
        ));
    }
    let mut distribution = distribution();
    distribution["artifacts"][0]["path"] = json!("bin/p2kes");
    assert!(normalize(&distribution).is_err());
    distribution["artifacts"][0]["path"] = json!(MANIFEST);
    distribution["artifacts"][0]["class"] = json!("bootstrap");
    assert!(normalize(&distribution).is_err());
}

fn write(root: &Path, path: &str, contents: &[u8], mode: u32) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn inventory_checks_exact_members_modes_and_hashes() {
    let scratch = PrivateDir::new().unwrap();
    let manifest = normalize(&distribution()).unwrap();
    for artifact in &manifest.artifacts {
        write(
            &scratch.0,
            &artifact.path,
            b"hello",
            payload_mode(&artifact.path),
        );
    }
    write(&scratch.0, MANIFEST, b"{}", 0o644);
    write(&scratch.0, MANIFEST_SIGNATURE, b"signature", 0o644);
    let root = open_bundle(&scratch.0).unwrap();
    verify_inventory(&root, &manifest.artifacts).unwrap();
    let mut staged = Vec::new();
    copy_verified_artifact(&scratch.0, &manifest.artifacts[0], &mut staged).unwrap();
    assert_eq!(staged, b"hello");

    write(&scratch.0, "extra", b"hello", 0o644);
    assert!(verify_inventory(&root, &manifest.artifacts).is_err());
    fs::remove_file(scratch.0.join("extra")).unwrap();
    write(&scratch.0, "bin/p2kes", b"hello", 0o644);
    assert!(verify_inventory(&root, &manifest.artifacts).is_err());
    write(&scratch.0, "bin/p2kes", b"HELLO", 0o755);
    assert!(matches!(
        verify_inventory(&root, &manifest.artifacts),
        Err(ReleaseError::HashMismatch { .. })
    ));
    write(&scratch.0, "bin/p2kes", b"longer", 0o755);
    assert!(matches!(
        verify_inventory(&root, &manifest.artifacts),
        Err(ReleaseError::SizeMismatch { .. })
    ));
    fs::remove_file(scratch.0.join("bin/p2kes")).unwrap();
    assert!(verify_inventory(&root, &manifest.artifacts).is_err());
}

#[test]
fn staged_copy_refuses_intermediate_symlinks_and_hardlinks() {
    let scratch = PrivateDir::new().unwrap();
    let outside = PrivateDir::new().unwrap();
    let manifest = normalize(&distribution()).unwrap();
    let artifact = &manifest.artifacts[0];
    write(&outside.0, "p2kesup", b"hello", 0o755);
    symlink(&outside.0, scratch.0.join("bin")).unwrap();
    assert!(copy_verified_artifact(&scratch.0, artifact, io::sink()).is_err());
    fs::remove_file(scratch.0.join("bin")).unwrap();
    fs::create_dir(scratch.0.join("bin")).unwrap();
    fs::hard_link(outside.0.join("p2kesup"), scratch.0.join(&artifact.path)).unwrap();
    assert!(copy_verified_artifact(&scratch.0, artifact, io::sink()).is_err());
}

#[test]
fn unsigned_legacy_manifest_is_not_a_fallback() {
    let scratch = PrivateDir::new().unwrap();
    write(
        &scratch.0,
        "release-manifest.json",
        br#"{
        "schema_version":2,"version":"0.2.0","usb_protocol_major":1,
        "platform":{"arch":"x86_64","os":"linux","min_glibc":"2.36"},"artifacts":[]
    }"#,
        0o644,
    );
    assert!(load_and_verify_manifest(&scratch.0).is_err());
    assert!(load_and_verify_firmware(&scratch.0).is_err());
}

#[test]
fn validates_committed_firmware_release_and_otp_policy_bounds() {
    let raw_policy = include_bytes!("../../../security/otp-policy.json");
    validate_otp_policy_bounds(raw_policy).unwrap();

    let mut bad_policy: Value = serde_json::from_slice(raw_policy).unwrap();
    bad_policy["firmware_region"]["end"] = json!(0x1040_0000u32);
    assert!(validate_otp_policy_bounds(&serde_json::to_vec(&bad_policy).unwrap()).is_err());

    let raw_release = include_bytes!(
        "../../../evidence/84df698978d37256de1bdf85cec940022d32ceaa-2593f2817f21af96923ca5693f5f776a1bd1d93c63d9c8b50e25249f06cfb92b/candidate-v0.1.0-rc.11/release.json"
    );
    let (tag, artifacts) = normalize_firmware_release(
        raw_release,
        "be364e660f6e7236cc14d3e74b33660311608fa78f38cd6cc5c4f031c910b8a0",
    )
    .unwrap();
    assert_eq!(tag, "v0.1.0-rc.11");
    assert_eq!(artifacts.len(), FIRMWARE_ARTIFACTS.len());

    assert!(normalize_firmware_release(raw_release, &"00".repeat(32)).is_err());
    let mut bad_release: Value = serde_json::from_slice(raw_release).unwrap();
    bad_release["firmware_region"]["end"] = json!(0x1040_0000u32);
    assert!(
        normalize_firmware_release(
            &serde_json::to_vec(&bad_release).unwrap(),
            "be364e660f6e7236cc14d3e74b33660311608fa78f38cd6cc5c4f031c910b8a0",
        )
        .is_err()
    );
}
