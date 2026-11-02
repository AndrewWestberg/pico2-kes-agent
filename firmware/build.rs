use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    fs::copy("memory.x", out.join("memory.x")).expect("copy firmware memory layout");
    fs::copy("image-def.x", out.join("image-def.x")).expect("copy RP2350 image definition layout");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=image-def.x");
    let names = [
        "P2KES_BUILD_VERSION",
        "P2KES_BUILD_ID",
        "P2KES_SOURCE_COMMIT",
    ];
    for name in names {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let values = names.map(|name| {
        env::var_os(name).map(|value| {
            value
                .into_string()
                .unwrap_or_else(|_| panic!("{name} must be UTF-8"))
        })
    });
    let [version, build_id, commit] = match values {
        [None, None, None] => [
            "development-unqualified".to_owned(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            "0000000000000000000000000000000000000000".to_owned(),
        ],
        [Some(version), Some(build_id), Some(commit)] => {
            assert!(
                !version.is_empty()
                    && version.len() <= 64
                    && version.bytes().all(|b| b.is_ascii_graphic()),
                "invalid P2KES_BUILD_VERSION"
            );
            assert!(
                build_id.len() == 64 && build_id.bytes().all(|b| b.is_ascii_hexdigit()),
                "firmware P2KES_BUILD_ID must be a 32-byte hexadecimal identifier"
            );
            assert!(
                (commit.len() == 40 || commit.len() == 64)
                    && commit.bytes().all(|b| b.is_ascii_hexdigit()),
                "P2KES_SOURCE_COMMIT must be a full hexadecimal commit"
            );
            [version, build_id, commit]
        }
        _ => panic!("firmware build metadata must be supplied together"),
    };
    println!("cargo:rustc-env=P2KES_FIRMWARE_VERSION={version}");
    println!("cargo:rustc-env=P2KES_FIRMWARE_BUILD_ID={build_id}");
    println!("cargo:rustc-env=P2KES_FIRMWARE_SOURCE_COMMIT={commit}");
}
