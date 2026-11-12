use std::fmt::Display;
use uuid::Uuid;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Generate},
};
use argon2::{Argon2, password_hash::phc::SaltString};
use base64::prelude::*;
use totp_rs::{Algorithm, Builder, Secret, Totp};

use crate::encrypted_storage::{EncryptedAccount, Storage};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub const DEFAULT_ALGO: Algorithm = Algorithm::SHA1;
pub const DEFAULT_DIGITS: usize = 6;
pub const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_SKEW: u16 = 1;

pub struct Password(pub String);

pub enum PasswordInvalidError {
    TooShort,
}

pub enum VaultDecryptError {
    DecryptFailed,
    Other(String),
}

impl Display for PasswordInvalidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Password is too short. Minimal length is {}",
            Password::MIN_SYMBOLS
        )
    }
}

impl Password {
    pub const MIN_SYMBOLS: usize = 4;
    pub fn from_string(value: String) -> Result<Self, PasswordInvalidError> {
        if value.len() < Password::MIN_SYMBOLS {
            return Err(PasswordInvalidError::TooShort);
        }
        Ok(Self(value))
    }
}

pub struct Account {
    pub id: Uuid,
    pub totp: Totp,
    pub created_at: i64,
    pub modified_at: i64,
    pub custom_position: usize,
}

impl Account {
    fn new(totp: Totp, custom_position: usize) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4(),
            totp,
            created_at: now,
            modified_at: now,
            custom_position,
        }
    }
    pub fn from_otp_auth_url(otp_auth_url: &str, position: usize) -> Result<Self, String> {
        Ok(Self::new(
            Totp::from_url(otp_auth_url).map_err(|e| format!("TOTP URL Init Error: {e}"))?,
            position,
        ))
    }

    pub fn from_manual_with_defaults(
        issuer: Option<String>,
        account_name: String,
        secret: String,
        position: usize,
    ) -> Result<Self, String> {
        Self::from_manual(
            issuer,
            account_name,
            DEFAULT_ALGO,
            DEFAULT_DIGITS,
            DEFAULT_PERIOD,
            secret,
            position,
        )
    }

    pub fn from_manual(
        issuer: Option<String>,
        account_name: String,
        algo: Algorithm,
        digits: usize,
        period: u64,
        secret_b32: String,
        position: usize,
    ) -> Result<Self, String> {
        let secret =
            Secret::try_from_base32(&secret_b32).map_err(|e| format!("Wrong Secret: {e}"))?;
        let totp = init_totp(
            issuer,
            account_name,
            algo,
            digits,
            period,
            secret.as_bytes().to_vec(),
        )?;
        Ok(Self::new(totp, position))
    }

    pub fn decrypted(
        key: &[u8; KEY_LEN],
        encrypted_account: &EncryptedAccount,
    ) -> Result<Self, VaultDecryptError> {
        let secret = decrypt_secret(&encrypted_account.encrypted_secret_b64, key)?;
        let totp = init_totp(
            encrypted_account.issuer.to_owned(),
            encrypted_account.account_name.to_owned(),
            encrypted_account.algo,
            encrypted_account.digits,
            encrypted_account.period,
            secret.to_owned(),
        )
        .map_err(|e| VaultDecryptError::Other(e.to_string()))?;
        Ok(Self {
            id: encrypted_account.id,
            totp,
            created_at: encrypted_account.created_at,
            modified_at: encrypted_account.modified_at,
            custom_position: encrypted_account.custom_position,
        })
    }

    pub fn current_state(&self) -> Result<(String, u64), String> {
        let totp = &self.totp;
        let remaining = totp.ttl();
        let code = totp.generate_current().to_string();
        Ok((code, remaining))
    }
}

pub struct Vault {
    pub master_key: [u8; KEY_LEN],
    pub salt: SaltString,
    pub accounts: Vec<Account>,
}

impl Vault {
    pub fn initialize(password: &Password) -> Result<Vault, String> {
        let salt = SaltString::generate();
        let master_key = master_key(&password.0, salt.as_ref())?;
        Ok(Vault {
            master_key,
            salt,
            accounts: Vec::new(),
        })
    }

    pub fn decrypt_storage(password: &str, storage: &Storage) -> Result<Vault, VaultDecryptError> {
        let master_key =
            master_key(password, &storage.salt_b64).map_err(VaultDecryptError::Other)?;
        let check_value = decrypt_secret(&storage.sealed_check, &master_key)?;
        if check_value != Storage::SEALED_CHECK {
            return Err(VaultDecryptError::Other("Wrong Check Value".to_string()));
        }
        let accounts: Result<Vec<Account>, VaultDecryptError> = storage
            .accounts
            .iter()
            .map(|enc| Account::decrypted(&master_key, enc))
            .collect();
        let accounts = accounts?;
        let salt = SaltString::from_b64(&storage.salt_b64)
            .map_err(|e| VaultDecryptError::Other(e.to_string()))?;
        Ok(Self {
            master_key,
            accounts,
            salt,
        })
    }
}

fn init_totp(
    issuer: Option<String>,
    account_name: String,
    algo: Algorithm,
    digits: usize,
    period: u64,
    secret: Vec<u8>,
) -> Result<Totp, String> {
    let digits = u8::try_from(digits).map_err(|e| format!("TOTP Init Error: {e}"))?;
    let short_secret = secret.len() == 10;
    let builder = Builder::new()
        .with_algorithm(algo)
        .with_digits(digits)
        .with_skew(DEFAULT_SKEW)
        .with_step_duration(period)
        .with_secret(secret)
        .with_issuer(issuer)
        .with_account_name(account_name);
    let totp = if short_secret {
        // Google Authenticator Compatibility
        builder.build_noncompliant()
    } else {
        builder
            .build()
            .map_err(|e| format!("TOTP Init Error: {e}"))?
    };
    Ok(totp)
}

pub fn encrypt_secret(secret: &[u8], key: &[u8; KEY_LEN]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::try_generate().map_err(|e| e.to_string())?;
    let cipher_text = cipher.encrypt(&nonce, secret).map_err(|e| e.to_string())?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&cipher_text);
    Ok(BASE64_STANDARD.encode(&combined))
}

fn master_key(password: &str, salt_b64: &str) -> Result<[u8; KEY_LEN], String> {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(salt_b64).map_err(|e| e.to_string())?;
    let mut key = [0u8; KEY_LEN];
    argon2
        // V1 derives the key from the encoded salt, not its decoded bytes.
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

fn decrypt_secret(
    encrypted_secret_b64: &str,
    key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, VaultDecryptError> {
    let combined = BASE64_STANDARD
        .decode(encrypted_secret_b64)
        .map_err(|e| VaultDecryptError::Other(e.to_string()))?;
    let (nonce_bytes, cipher_text) = combined
        .split_at_checked(NONCE_LEN)
        .ok_or_else(|| VaultDecryptError::Other("Invalid encrypted secret length".to_string()))?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| VaultDecryptError::Other(e.to_string()))?;
    let nonce =
        Nonce::try_from(nonce_bytes).map_err(|e| VaultDecryptError::Other(e.to_string()))?;
    cipher
        .decrypt(&nonce, cipher_text)
        .map_err(|_| VaultDecryptError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_rfc6238() {
        for (algorithm, secret, expected) in [
            (
                Algorithm::SHA1,
                b"12345678901234567890".as_slice(),
                "94287082",
            ),
            (
                Algorithm::SHA256,
                b"12345678901234567890123456789012".as_slice(),
                "46119246",
            ),
            (
                Algorithm::SHA512,
                b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
                "90693936",
            ),
        ] {
            let totp =
                init_totp(None, "test".to_string(), algorithm, 8, 30, secret.to_vec()).unwrap();
            assert_eq!(totp.generate(59).to_string(), expected);
        }
    }

    #[test]
    fn storage_round_trip_preserves_accounts() {
        let mut vault = Vault::initialize(&Password("test-password".to_string())).unwrap();
        for secret in ["1234567890", "12345678901234567890"] {
            let totp = init_totp(
                Some("Issuer".to_string()),
                "user".to_string(),
                DEFAULT_ALGO,
                6,
                30,
                secret.as_bytes().to_vec(),
            )
            .unwrap();
            vault
                .accounts
                .push(Account::new(totp, vault.accounts.len()));
        }
        let storage = Storage::encrypt_vault(&vault).unwrap();
        let json = serde_json::to_string(&storage).unwrap();
        let storage = serde_json::from_str(&json).unwrap();
        let decrypted = Vault::decrypt_storage("test-password", &storage)
            .ok()
            .unwrap();
        assert_eq!(vault.accounts.len(), decrypted.accounts.len());
        for (old, new) in vault.accounts.iter().zip(&decrypted.accounts) {
            assert_eq!(old.id, new.id);
            assert_eq!(old.created_at, new.created_at);
            assert_eq!(old.modified_at, new.modified_at);
            assert_eq!(old.custom_position, new.custom_position);
            assert_eq!(old.totp.issuer(), new.totp.issuer());
            assert_eq!(old.totp.account_name(), new.totp.account_name());
            assert_eq!(old.totp.secret().as_bytes(), new.totp.secret().as_bytes());
            assert_eq!(old.totp.algorithm(), new.totp.algorithm());
            assert_eq!(old.totp.digits(), new.totp.digits());
            assert_eq!(old.totp.step(), new.totp.step());
            assert_eq!(
                old.totp.generate(59).to_string(),
                new.totp.generate(59).to_string()
            );
        }
    }

    #[test]
    fn account_import_supports_manual_and_otp_auth_url() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let manual = Account::from_manual_with_defaults(
            Some("Issuer".to_string()),
            "user".to_string(),
            secret.to_string(),
            0,
        )
        .unwrap();
        let url = Account::from_otp_auth_url(
            &format!("otpauth://totp/Issuer:user?secret={secret}&issuer=Issuer"),
            0,
        )
        .unwrap();
        assert_eq!(manual.totp, url.totp);
        assert!(
            Account::from_manual_with_defaults(
                None,
                "user".to_string(),
                "JBSWY3DPEHPK3PXP".to_string(),
                0,
            )
            .is_ok()
        );
    }
}
