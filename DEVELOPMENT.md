# Development

## Requirements

- Rust stable and Cargo; run commands from the repository root.
- macOS: Xcode Command Line Tools, including Swift.
- Windows: MSVC toolchain and Windows SDK.
- Linux: native build dependencies listed in [the packaging workflow](.github/workflows/bundle.yml); system unlock also needs [platform services and the Polkit policy](crates/system-protection/README.md).

## Build and run

```sh
cargo build --release --locked
cargo run --release
```

- Binary: `target/release/factr-auth` (`factr-auth.exe` on Windows).
- The root application is the default Cargo target.

## Checks

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Packaging

- **macOS / Windows:** install `cargo-packager` and run on the respective OS:

```sh
cargo install cargo-packager --version 0.11.8 --locked
cargo packager --release --formats dmg  # macOS
cargo packager --release --formats nsis # Windows
```

- Configuration: `Cargo.toml`; output: `target/release/`.
- **Linux:** install Python 3 and [nFPM](https://nfpm.goreleaser.com/), then run:

```sh
./packaging/linux/package.sh
```

- Builds the release binary and creates DEB, RPM, and Arch (`.pkg.tar.zst`) files with the Polkit policy in `target/packages/`.
- Version and architecture are detected automatically; configuration: `packaging/linux/nfpm.yaml`.
- [Release workflow](.github/workflows/bundle.yml): manual platform selection, packaging, and optional draft release. Uses the same Linux script.

## Structure and architecture

| Path | Responsibility |
| --- | --- |
| `src/` | Application, configuration, unlock orchestration |
| `src/app.rs`, `src/app/` | UI composition, action handlers, display updates |
| `src/vault_access.rs` | Vault access operations and background jobs, independent of egui |
| `src/view/` | egui widgets and view models |
| `crates/core/` | Domain models, TOTP, encryption, recovery keys |
| `crates/storage/` | File formats, migration, atomic writes |
| `crates/system-protection/` | Platform authentication and key protection |
| `packaging/`, `.github/` | Linux package definitions and CI workflows |
| `assets/`, `locales/` | Fonts, icons, translations |

- The app depends on all three crates; storage and system protection depend on core.
- The library crates have no egui dependency. Native code stays in system protection.
- Shared dependency versions are declared in the workspace `Cargo.toml`.
- Vault protection and limitations: [SECURITY.md](SECURITY.md).
