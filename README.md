<p align="center">
  <img src="docs/factr_git_template.png" width="1280" alt="Factr Logo Banner">
</p>

# Factr.

An opinionated desktop TOTP authenticator.

No registration, no servers, fully yours.

No background services, no menu bar widgets, just a fast open then close utility.

## Screenshots

![Main screen](docs/screenshots/factr_screenshot_main.png)

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/factr_screenshot_search.png" alt="Account Search" width="100%"></td>
    <td width="50%"><img src="docs/screenshots/factr_screenshot_sort.png" alt="Account Sorting" width="100%"></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/factr_screenshot_unlock.png" alt="Vault Unlock" width="100%"></td>
    <td width="50%"><img src="docs/screenshots/factr_screenshot_windows.png" alt="Application Windows" width="100%"></td>
  </tr>
</table>

## Features

- fast and lightweight
- minimal UI
- security-conscious
- Windows, Linux, macOS
- written in Rust
- easy backup and restore

## Install

### Homebrew (macOS 11+)

```sh
brew tap vadimware/tap
brew install --cask factr
```

### Manually

#### Supported Platforms

- macOS: 11+ (Big Sur) Apple Silicon/Intel
- Windows: 10/11 x64/ARM64
- Linux 64-bit: amd64/arm64 glibc 2.35+ (Ubuntu 22.04+, Debian 12+)

[Download from Releases Page](https://github.com/vadimware/factr/releases/latest)

#### Ubuntu/Debian Based (DEB)

Use this command to install the downloaded package file:

```sh
sudo apt install ./Factr_*_linux-*.deb # Use downloaded package name
```

#### Fedora (RPM)

Use this command to install the downloaded package file:

```sh
sudo dnf install ./Factr_*_linux-*.rpm # Use downloaded package name
```

#### Arch Based

Use this command to install the downloaded package file:

```sh
sudo pacman -U ./Factr_*_linux-*.pkg.tar.zst # Use downloaded package name
```

## Overview

I couldn't find a decent, minimal, open-source desktop authenticator, so I decided to build my own.

**Factr is a small utility without any clouds or servers, without any background tray items**, meant for “open, unlock, grab the code, then close” usage. An optional autolock timeout is available for longer sessions.

It’s really simple: the app uses just `~/.config/factr` with `config.json` for settings and `storage.json` for a securely encrypted vault.
Sensitive data is present in memory while the vault is unlocked. On locking, it is cleared from memory where possible. On disk, account data is encrypted.

It uses OS-native security mechanisms so there is no need to set up a new password for this, and it is practically the only method to secure data locally without a huge password to remember.
But you need to **save the recovery key somewhere** as a fallback option or for transferring the vault to another system.

The transfer feature is already built in: just copy the `~/.config/factr` directory and the app will guide you through recovery and setting up system protection on the new system.

See [SECURITY.md](docs/SECURITY.md) for vault encryption, recovery, and system protection.

See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for building, packaging, and project structure.

## Tips

1. With sorting disabled, you can arrange codes as you want just by dragging them!
2. To search results by relevance, disable sorting after typing in the search bar
3. To transfer to another system or device, just copy the `~/.config/factr` directory and grab your recovery key
4. You can make the app close automatically after copying the code in Settings
5. There is no "batch export" feature for security reasons. But you can copy links one by one to do that. (IMO it is very easy to forget to delete a file with unencrypted secrets on the device)

## Credits

Third-party licenses and attribution notices: [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
