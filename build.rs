use std::env;

fn main() {
    const NAMES: [&str; 3] = [
        "P2KES_BUILD_VERSION",
        "P2KES_BUILD_ID",
        "P2KES_SOURCE_COMMIT",
    ];
    for name in NAMES {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let values = NAMES.map(|name| {
        env::var_os(name).map(|value| {
            value
                .into_string()
                .unwrap_or_else(|_| panic!("{name} must be UTF-8"))
        })
    });
    let [version, build_id, commit] = match values {
        [None, None, None] => [
            "development".to_owned(),
            "development".to_owned(),
            "development".to_owned(),
        ],
        [Some(version), Some(build_id), Some(commit)] => {
            assert!(
                !version.is_empty()
                    && version.len() <= 64
                    && version.bytes().all(|b| b.is_ascii_graphic()),
                "invalid P2KES_BUILD_VERSION"
            );
            assert!(
                !build_id.is_empty()
                    && build_id.len() <= 64
                    && build_id.bytes().all(|b| b.is_ascii_graphic()),
                "invalid P2KES_BUILD_ID"
            );
            assert!(
                (commit.len() == 40 || commit.len() == 64)
                    && commit.bytes().all(|b| b.is_ascii_hexdigit()),
                "P2KES_SOURCE_COMMIT must be a full hexadecimal commit"
            );
            [version, build_id, commit]
        }
        _ => panic!("release build metadata must be supplied together"),
    };
    println!("cargo:rustc-env=P2KES_EMBEDDED_VERSION={version}");
    println!("cargo:rustc-env=P2KES_EMBEDDED_BUILD_ID={build_id}");
    println!("cargo:rustc-env=P2KES_EMBEDDED_SOURCE_COMMIT={commit}");
}
