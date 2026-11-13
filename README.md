<p align="center">
  <img src="docs/factr_git_template.png" width="1280" alt="Скриншот">
</p>

# Factr.

Desktop 2FA TOTP authenticator application.

No registration, no servers, fully yours.

No background services, no menu bar widgets, just fast open then close utility.

# Install

## Homebrew (macOS 11+)

```sh
brew tap lilvadim/tap
brew install --cask factr
```

## Manually

### Supported Platforms

- macOS: 11+ (Big Sur) Apple Silicon/Intel
- Windows: 10/11 x64/ARM64
- Linux 64-bit: amd64/arm64 glibc 2.35+ (Ubuntu 22.04+, Debian 12+)

[Download from Releases Page](https://github.com/lilvadim/factr/releases)

## Features

- fast
- minimal
- secure
- mostly handcoded
- Windows, Linux, macOS
- written in Rust

## Tips

1. While sort is disabled, you can arrange codes as you want just dragging them!
2. To search by relevance, disable sort after typing in search bar

## Vault protection

V2 encrypts all account data with a random 256-bit key. A separate recovery
key protects a copy of that key and can open the vault on any supported OS.
Keep the recovery key somewhere safe, separately from the vault file. There
is no short password or PIN fallback in V2.

On supported Macs, enable system authentication during setup or in Settings.
Factr uses CryptoKit and Secure Enclave with mandatory user presence (Touch ID
or the system password). The device-bound key representation is stored in the
vault; this does not require a paid Apple developer account or Keychain access
group entitlements. Native authentication runs outside the UI thread.

Windows and Linux currently support recovery-key unlock; their system
protection providers are not implemented yet. Protected keys from other or
unknown providers are preserved when saving the vault on another OS.

To transfer a vault, copy its file and open it with the recovery key. On a
supported Mac, system protection can then be added for the new device.

The unlocked app necessarily holds decrypted secrets in memory. System
protection does not guarantee safety on a compromised computer.

Building on macOS additionally requires the Swift compiler from Xcode or
Command Line Tools. Other platforms do not compile or link the Swift module.

## Screenshots

![Screenshot](docs/screenshot.png)
![Screenshot Locked](docs/screenshot_locked.png)
![Screenshot All Windwos](docs/screenshot_all.png)
