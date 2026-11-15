use factr_core::error::{AccountError, RecoveryError, VaultDecryptError, VaultEncryptError};
use factr_storage::{InitializationError, StorageError, migration::MigrationError};
use factr_system_protection::SystemProtectionError;
use rust_i18n::t;

use super::{error::AppError, task::TaskError};

/// Formats an application error at the presentation boundary.
pub(super) fn app_error(error: &AppError) -> String {
    match error {
        AppError::Account(error) => account_error(error),
        AppError::Recovery(error) => recovery_error(error),
        AppError::Decrypt(error) => decrypt_error(error),
        AppError::Storage(error) => storage_error(error),
        AppError::Initialization(error) => initialization_error(error),
        AppError::SystemProtection(error) => system_protection_error(error),
        AppError::ExpectedV2 => t!("errors.expected-v2").into(),
        AppError::MissingSystemKey => t!("errors.system-key-missing").into(),
        AppError::NoVault => t!("errors.no-vault").into(),
        AppError::NoAccount => t!("errors.no-account").into(),
    }
}

/// Formats task failures without converting domain errors in the worker.
pub(super) fn task_error(error: TaskError<AppError>) -> String {
    match error {
        TaskError::Operation(error) => app_error(&error),
        TaskError::Stopped => t!("errors.background-stopped").into(),
    }
}

/// Formats account validation errors without exposing account input.
fn account_error(error: &AccountError) -> String {
    match error {
        AccountError::InvalidSecret(_) => t!("errors.invalid-secret").into(),
        AccountError::InvalidDigits => t!("errors.invalid-digits").into(),
        AccountError::InvalidOtpAuthUrl(error) | AccountError::InvalidParameters(error) => {
            match error {
                totp_rs::TotpError::InvalidDigits { .. }
                | totp_rs::TotpError::DigitsParse { .. } => t!("errors.invalid-digits").into(),
                totp_rs::TotpError::InvalidStepZero | totp_rs::TotpError::StepParse { .. } => {
                    t!("errors.invalid-period").into()
                }
                totp_rs::TotpError::InvalidSecret | totp_rs::TotpError::SecretNotSet => {
                    t!("errors.invalid-secret").into()
                }
                totp_rs::TotpError::SecretTooShort { .. } => t!("errors.secret-too-short").into(),
                totp_rs::TotpError::InvalidAlgorithm { .. } => {
                    t!("errors.invalid-algorithm").into()
                }
                totp_rs::TotpError::InvalidAccountName { .. }
                | totp_rs::TotpError::AccountNameNotSet
                | totp_rs::TotpError::AccountNameDecode { .. } => {
                    t!("errors.invalid-account-name").into()
                }
                totp_rs::TotpError::InvalidIssuer { .. }
                | totp_rs::TotpError::IssuerDecode { .. }
                | totp_rs::TotpError::IssuerMismatch { .. } => t!("errors.invalid-issuer").into(),
                _ => t!("errors.invalid-otp-url").into(),
            }
        }
    }
}

/// Formats recovery-key validation and unwrap failures.
fn recovery_error(error: &RecoveryError) -> String {
    match error {
        RecoveryError::InvalidFormat => t!("errors.invalid-recovery-format").into(),
        RecoveryError::IncorrectKey => t!("errors.incorrect-recovery-key").into(),
        RecoveryError::InvalidVaultKey => t!("errors.invalid-vault-data").into(),
        RecoveryError::Encryption(error) => encrypt_error(error),
    }
}

/// Formats encryption failures.
fn encrypt_error(error: &VaultEncryptError) -> String {
    match error {
        VaultEncryptError::RandomGenerationFailed => t!("errors.random-generation-failed").into(),
        VaultEncryptError::EncryptionFailed => t!("errors.encryption-failed").into(),
    }
}

/// Formats decryption failures without assuming a password was used.
fn decrypt_error(error: &VaultDecryptError) -> String {
    match error {
        VaultDecryptError::DecryptFailed => t!("errors.decryption-failed").into(),
        VaultDecryptError::InvalidEncoding(_)
        | VaultDecryptError::InvalidPayload
        | VaultDecryptError::InvalidAccounts(_) => t!("errors.invalid-vault-data").into(),
    }
}

/// Formats file access and serialization failures.
pub(super) fn storage_error(error: &StorageError) -> String {
    match error {
        StorageError::Read(error) => match error.kind() {
            std::io::ErrorKind::NotFound => t!("errors.vault-not-found").into(),
            std::io::ErrorKind::PermissionDenied => t!("errors.vault-read-denied").into(),
            _ => t!("errors.vault-read-failed").into(),
        },
        StorageError::Write(error) => {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                t!("errors.vault-write-denied").into()
            } else {
                t!("errors.vault-write-failed").into()
            }
        }
        StorageError::Deserialize(_) => t!("errors.invalid-vault-format").into(),
        StorageError::Serialize(_) => t!("errors.vault-serialize-failed").into(),
        StorageError::Encryption(error) => encrypt_error(error),
    }
}

/// Formats new-vault and migration failures while retaining the pending setup.
pub(super) fn initialization_error(error: &InitializationError) -> String {
    match error {
        InitializationError::Storage(error) => storage_error(error),
        InitializationError::Recovery(error) => recovery_error(error),
        InitializationError::Verification(error) => decrypt_error(error),
        InitializationError::SourceChanged => t!("errors.vault-changed").into(),
        InitializationError::Migration(error) => match error {
            MigrationError::Decrypt(VaultDecryptError::DecryptFailed) => {
                t!("wrong-password").into()
            }
            MigrationError::Decrypt(error) => decrypt_error(error),
            MigrationError::AlreadyCurrent => t!("errors.already-current").into(),
            MigrationError::InvalidSalt(_)
            | MigrationError::KeyDerivation(_)
            | MigrationError::InvalidCheck
            | MigrationError::InvalidAccount(_) => t!("errors.invalid-vault-data").into(),
        },
    }
}

/// Formats platform protection failures without parsing native messages.
pub(super) fn system_protection_error(error: &SystemProtectionError) -> String {
    match error {
        SystemProtectionError::UnsupportedPlatform => t!("errors.unsupported-platform").into(),
        SystemProtectionError::UnsupportedKey | SystemProtectionError::KeyMismatch => {
            t!("errors.non-local-key").into()
        }
        SystemProtectionError::KeyMissing => t!("errors.system-key-missing").into(),
        SystemProtectionError::InvalidKey => t!("errors.invalid-system-key").into(),
        SystemProtectionError::AuthenticationCancelled => {
            t!("errors.authentication-cancelled").into()
        }
        SystemProtectionError::AuthenticationDenied => t!("errors.authentication-denied").into(),
        SystemProtectionError::MissingPolicy => t!("errors.missing-policy").into(),
        SystemProtectionError::SecretServiceUnavailable => {
            t!("errors.secret-service-unavailable").into()
        }
        SystemProtectionError::PolkitUnavailable => t!("errors.polkit-unavailable").into(),
        SystemProtectionError::DeviceIdentityUnavailable => {
            t!("errors.device-identity-unavailable").into()
        }
        SystemProtectionError::SettingsUnavailable => t!("errors.settings-unavailable").into(),
        SystemProtectionError::InvalidResponse
        | SystemProtectionError::StateUnavailable
        | SystemProtectionError::Platform(_) => t!("errors.system-protection-failed").into(),
        SystemProtectionError::Encryption(error) => encrypt_error(error),
        SystemProtectionError::Decryption(error) => decrypt_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_and_damaged_vault_errors_are_not_reported_as_wrong_password() {
        let recovery = AppError::Recovery(RecoveryError::IncorrectKey);
        assert_eq!(app_error(&recovery), t!("errors.incorrect-recovery-key"));
        assert_ne!(app_error(&recovery), t!("wrong-password"));
        let migration = InitializationError::Migration(MigrationError::Decrypt(
            VaultDecryptError::DecryptFailed,
        ));
        assert_eq!(initialization_error(&migration), t!("wrong-password"));
        let damaged = InitializationError::Migration(MigrationError::Decrypt(
            VaultDecryptError::InvalidPayload,
        ));
        assert_eq!(
            initialization_error(&damaged),
            t!("errors.invalid-vault-data")
        );
        assert_eq!(
            t!("errors.authentication-cancelled", locale = "ru"),
            "Системная авторизация отменена."
        );
        assert_eq!(
            t!("errors.authentication-cancelled", locale = "en"),
            "System authentication was cancelled."
        );
    }
}
