# Vault protection

- V2 encrypts account data with AES-256-GCM and a random 256-bit vault key.
- A separate random recovery key encrypts a copy of the vault key.
- Keep the recovery key separately from the vault file. V2 has no password or PIN fallback.
- Transfer: copy the vault file, unlock with the recovery key, then enable protection on the new device.
- Migration replaces V1 after recovery-key confirmation, without creating a V1 backup.

## System unlock

- **macOS:** CryptoKit and Secure Enclave; Touch ID or system password authorizes key agreement. The app derives a wrapping key and decrypts the vault key. The saved Secure Enclave key representation is device-bound; no paid developer account is required.
- **Linux:** Secret Service stores a random wrapping key; Polkit requests authentication before the app retrieves it. DEB/RPM/Arch packages include the required policy. No TPM is required.
- **Windows:** Windows Hello signs a random challenge; the signature derives the wrapping key. Credential Manager stores the challenge and encrypted vault key. Requires configured Windows Hello (PIN, fingerprint, or face).
- Keys protected by other or unknown providers are preserved when saving.

## Limits

- On Linux, another unsandboxed process running as the same user may read the wrapping key from an unlocked Secret Service without Polkit confirmation.
- An unlocked app holds decrypted secrets in memory; system protection cannot guarantee safety on a compromised computer.
- The vault file and recovery key together allow access without system authentication.
