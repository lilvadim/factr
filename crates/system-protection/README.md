# factr-system-protection

- OS-backed vault key protection; depends on `factr-core`, independent of egui.
- Authentication runs on the application's worker thread.
- Security guarantees and limitations: [SECURITY.md](../../SECURITY.md).

## macOS

- Swift bridge using CryptoKit, Secure Enclave, and system authentication.
- Requires a supported Mac and Swift from Xcode or Command Line Tools to build.
- Device-bound protection; no paid developer account or Keychain access group needed.

## Linux

- Secret Service (GNOME Keyring or compatible KWallet), D-Bus, Polkit, and an authentication agent.
- Wrapping key in Secret Service; encrypted vault key in the vault file.
- Polkit uses `auth_self` without retained authorization; no TPM or custom daemon.
- DEB/RPM/Arch packages install the policy automatically. For source builds, run from the repository root and restart Factr:

```sh
sudo install -o root -g root -m 0644 crates/system-protection/linux/com.factr.policy /usr/share/polkit-1/actions/com.factr.policy
```

## Tests

- Interactive tests require the platform services and user confirmation:

```sh
cargo test -p factr-system-protection -- --ignored
```
