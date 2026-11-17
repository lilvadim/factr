# System protection

- **System protection:** use your system password, PIN, or biometrics for everyday unlocking.
- **Recovery key:** save it safely, separately from your vault. You need it to move your vault or restore access.
- Without system protection, you need the recovery key every time which is not very useful.

## Windows 10 and 11

1. Open **Settings → Accounts → Sign-in options**. Factr’s **Open sign-in settings** link opens this page.
2. Set up **PIN (Windows Hello)**. Fingerprint and face recognition are optional.
3. Return to Factr. Click **Done**, then enable system protection.

**Compatibility:** Factr does not explicitly require a TPM. A PIN needs no fingerprint reader or special camera. Availability also depends on your Windows account and system policies.

If the check fails, review your [Windows Hello settings](https://support.microsoft.com/en-us/accounts-billing/security/sign-in-options-in-windows). You can still unlock with your recovery key.

## Linux

- Install the Factr **DEB, RPM, or Arch package**. It includes the required Polkit policy.
- Choose **one keyring provider** for your desktop: GNOME Keyring or KWallet.
- Your desktop also needs a **Polkit authentication agent** to show confirmation prompts. GNOME and Plasma normally include one.
- You can install the keyring after installing Factr. The policy does not need reinstalling.

### GNOME, Xfce, Cinnamon, and other desktops

Install missing packages for your distribution:

```sh
# Debian / Ubuntu
sudo apt update
sudo apt install gnome-keyring seahorse

# Fedora
sudo dnf install gnome-keyring seahorse

# Arch
sudo pacman -Syu gnome-keyring seahorse
```

1. Open **Passwords and Keys** (Seahorse).
2. Create or unlock a password-protected login keyring.
3. In Factr, click **Check again**, then enable system protection.
4. If the service is still unavailable, sign out and back in. Outside GNOME, you may also need to enable GNOME Keyring in session startup settings.

### KDE Plasma

Install missing packages for your distribution:

```sh
# Debian 13 / Plasma 6
sudo apt update
sudo apt install kwallet6 kwalletmanager

# Ubuntu 24.04 / Plasma 5
sudo apt update
sudo apt install libkf5wallet-bin kwalletmanager

# Fedora / Plasma 6
sudo dnf install kf6-kwallet kwalletmanager5

# Arch / Plasma 6
sudo pacman -Syu kwallet kwalletmanager
```

1. Open **System Settings → KDE Wallet**.
2. Enable the wallet system. Create or unlock your default wallet.
3. Enable **Use KWallet for the Secret Service interface**, if shown.
4. In Factr, click **Check again**, then enable system protection.
5. If the service is still unavailable, sign out and back in.

**Compatibility:** Secret Service requires [KWallet 5.97 or later](https://kde.org/announcements/frameworks/5/5.97.0/). Ubuntu 22.04’s stock KWallet is too old. Use GNOME Keyring or upgrade your desktop.

### If protection is still unavailable

Run these commands in your desktop terminal, without `sudo`:

```sh
# Check the keyring service
busctl --user introspect org.freedesktop.secrets /org/freedesktop/secrets

# Check Factr’s policy
pkaction --action-id com.factr.unlock
```

- Keyring check fails: check your provider and session startup settings.
- Policy check fails: reinstall the Factr package.
- No confirmation prompt: check that your session runs a Polkit authentication agent.
- **Check again** checks prerequisites. Enabling protection also tests authorization and key storage.

**Linux limitation:** other apps running as your user may read the stored key without Factr’s confirmation prompt. See [SECURITY.md](../docs/SECURITY.md).

## macOS

- Requires a compatible **Secure Enclave** and system authentication.
- Macs with **Apple silicon or T2** have the relevant hardware. Factr checks availability.
- Use your Mac login password or **Touch ID**. Touch ID is optional.
- Enable system protection in Factr and approve the macOS prompt.
- On unsupported Macs, use your recovery key.

More: [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web).
