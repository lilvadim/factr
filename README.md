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

[Download from Releases Page](https://github.com/lilvadim/factr/releases/latest)

#### Ubuntu/Debian Based (DEB)

Use this command to install downloaded package file:

```sh
sudo apt install <DOWNLOADED_PACKAGE>
```

#### Fedora (RPM)

Use this command to install downloaded package file:

```sh
sudo dnf install <DOWNLOADED_PACKAGE>
```

#### Arch Based

```sh
sudo pacman -U <DONWLOADED_PACKAGE>
```

## Features

- fast
- minimal
- secure
- Windows, Linux, macOS
- written in Rust

## Tips

1. While sort is disabled, you can arrange codes as you want just dragging them!
2. To search by relevance, disable sort after typing in search bar

## Screenshots

![Screenshot](docs/screenshot.png)
![Screenshot Locked](docs/screenshot_locked.png)
![Screenshot All Windwos](docs/screenshot_all.png)

See [SECURITY.md](SECURITY.md) for vault encryption, recovery, and system protection.

See [DEVELOPMENT.md](DEVELOPMENT.md) for building, packaging, and project structure.
