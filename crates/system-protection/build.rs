fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        build_macos_protection();
    }
}

/// Compiles and links the native macOS protection bridge.
fn build_macos_protection() {
    use std::{path::PathBuf, process::Command};

    println!("cargo::rerun-if-changed=src/macos.swift");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        arch => panic!("Unsupported macOS architecture: {arch}"),
    };
    let status = Command::new("xcrun")
        .args([
            "swiftc",
            "-parse-as-library",
            "-emit-object",
            "-O",
            "-module-name",
            "FactrSystemProtection",
            "-target",
        ])
        .arg(format!("{arch}-apple-macosx11.0"))
        .arg("-module-cache-path")
        .arg(out.join("swift-cache"))
        .arg("src/macos.swift")
        .arg("-o")
        .arg(out.join("system_protection.o"))
        .status()
        .expect("Cannot run the Swift compiler");
    assert!(
        status.success(),
        "Failed to compile macOS system protection"
    );
    // A native archive propagates the Swift object to dependent binaries.
    cc::Build::new()
        .object(out.join("system_protection.o"))
        .compile("factr_system_protection");
    let swift = Command::new("xcrun")
        .args(["--find", "swiftc"])
        .output()
        .expect("Cannot locate Swift");
    assert!(swift.status.success(), "Cannot locate Swift");
    let swift = PathBuf::from(String::from_utf8(swift.stdout).unwrap().trim());
    let libraries = swift
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("lib/swift/macosx");
    println!("cargo::rustc-link-search=native={}", libraries.display());
    println!("cargo::rustc-link-search=native=/usr/lib/swift");
    println!("cargo::rustc-link-lib=swiftCore");
}
