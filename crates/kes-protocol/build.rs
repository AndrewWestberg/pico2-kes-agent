use std::{collections::BTreeMap, env, fs, path::PathBuf};

// The authorization statement is a flat JSON object with ASCII keys and values.
// Reject duplicate keys, escapes and extensions rather than guessing a key.
fn parse(input: &str) -> Option<[u8; 32]> {
    let mut s = input
        .trim()
        .strip_prefix('{')?
        .trim()
        .strip_suffix('}')?
        .trim();
    let mut fields = BTreeMap::new();
    while !s.is_empty() {
        let rest = s.strip_prefix('"')?;
        let (key, rest) = rest.split_once('"')?;
        let rest = rest.trim_start().strip_prefix(':')?.trim_start();
        let (value, rest, quoted) = if let Some(rest) = rest.strip_prefix('"') {
            let (v, r) = rest.split_once('"')?;
            if v.contains('\\') {
                return None;
            }
            (v, r, true)
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            (rest[..end].trim(), &rest[end..], false)
        };
        if fields.insert(key, (value, quoted)).is_some() {
            return None;
        }
        let rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        s = rest.strip_prefix(',')?.trim_start();
        if s.is_empty() {
            return None;
        }
    }
    if fields.len() != 7
        || fields.get("schema_version") != Some(&("1", false))
        || fields.get("purpose") != Some(&("pico2-kes-firmware-boot-authority-v1", true))
        || fields.get("project")
            != Some(&("https://github.com/AndrewWestberg/pico2-kes-agent", true))
        || fields.get("algorithm") != Some(&("secp256k1", true))
        || fields.get("bootkey_slot") != Some(&("0", false))
    {
        return None;
    }
    fn hex(s: &str) -> Option<[u8; 32]> {
        if s.len() != 64
            || !s
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return None;
        }
        let mut result = [0; 32];
        for (i, v) in result.iter_mut().enumerate() {
            *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(result)
    }
    let (pem, pem_quoted) = *fields.get("public_pem_sha256")?;
    let (key, key_quoted) = *fields.get("bootkey_sha256")?;
    if !pem_quoted || !key_quoted {
        return None;
    }
    hex(pem)?;
    hex(key)
}
fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../../security/firmware-key.json");
    println!("cargo:rerun-if-changed={}", root.display());
    println!("cargo:rerun-if-env-changed=PICO2_REQUIRE_FIRMWARE_AUTHORITY");
    let key = fs::read_to_string(root).ok().and_then(|s| parse(&s));
    if key.is_none()
        && env::var_os("PICO2_REQUIRE_FIRMWARE_AUTHORITY").as_deref()
            == Some(std::ffi::OsStr::new("1"))
    {
        panic!("missing or invalid public firmware authority");
    }
    let code = format!(
        "pub const AUTHORIZED_BOOTKEY: Option<[u8; 32]> = {:?};\n",
        key
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("authorized_bootkey.rs"),
        code,
    )
    .unwrap();
}
