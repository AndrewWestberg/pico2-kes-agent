use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    fs::copy("memory.x", out.join("memory.x")).expect("copy firmware memory layout");
    fs::copy("image-def.x", out.join("image-def.x")).expect("copy RP2350 image definition layout");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=image-def.x");
}
