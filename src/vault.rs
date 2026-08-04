use std::fmt::Display;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use argon2::{Argon2, password_hash::SaltString};
use base64::prelude::*;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::encrypted_storage::{EncryptedAccount, Storage};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub const DEFAULT_ALGO: Algorithm = Algorithm::SHA1;
pub const DEFAULT_DIGITS: usize = 6;
pub const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_SKEW: u8 = 1;

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
    pub totp: TOTP,
}

impl Account {
    pub fn from_otp_auth_url(otp_auth_url: &str) -> Result<Self, String> {
        Ok(Self {
            totp: TOTP::from_url(otp_auth_url).map_err(|e| format!("TOTP URL Init Error: {e}"))?,
        })
    }

    pub fn from_manual_with_defaults(
        issuer: Option<String>,
        account_name: String,
        secret: String,
    ) -> Result<Self, String> {
        Self::from_manual(
            issuer,
            account_name,
            DEFAULT_ALGO,
            DEFAULT_DIGITS,
            DEFAULT_PERIOD,
            secret,
        )
    }

    pub fn from_manual(
        issuer: Option<String>,
        account_name: String,
        algo: Algorithm,
        digits: usize,
        period: u64,
        secret_b32: String,
    ) -> Result<Self, String> {
        let secret = Secret::Encoded(secret_b32)
            .to_bytes()
            .map_err(|e| format!("Wrong Secret: {e}"))?;
        let totp = init_totp(issuer, account_name, algo, digits, period, secret)?;
        Ok(Self { totp })
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
        Ok(Self { totp })
    }

    pub fn current_state(&self) -> Result<(String, u64), String> {
        let totp = &self.totp;
        let remaining = totp.ttl().map_err(|e| format!("Cannot get ttl: {e}"))?;
        let code = totp
            .generate_current()
            .map_err(|e| format!("Cannot generate code: {e}"))?;
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
        let salt = SaltString::generate(&mut OsRng);
        let master_key = master_key(&password.0, salt.as_str())?;
        Ok(Vault {
            master_key,
            salt,
            accounts: Vec::new(),
        })
    }

    pub fn decrypt_storage(password: &str, storage: &Storage) -> Result<Vault, VaultDecryptError> {
        let master_key =
            master_key(password, &storage.salt_b64).map_err(VaultDecryptError::Other)?;
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
) -> Result<TOTP, String> {
    let totp = if secret.len() != 10 {
        TOTP::new(
            algo,
            digits,
            DEFAULT_SKEW,
            period,
            secret,
            issuer,
            account_name,
        )
        .map_err(|e| format!("TOTP Init Error: {e}"))?
    } else {
        // Google Authenticator Compatibility
        TOTP::new_unchecked(
            algo,
            digits,
            DEFAULT_SKEW,
            period,
            secret,
            issuer,
            account_name,
        )
    };
    Ok(totp)
}

pub fn encrypt_secret(secret: &[u8], key: &[u8; KEY_LEN]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher_text = cipher.encrypt(nonce, secret).map_err(|e| e.to_string())?;
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&cipher_text);
    Ok(BASE64_STANDARD.encode(&combined))
}

fn master_key(password: &str, salt_b64: &str) -> Result<[u8; KEY_LEN], String> {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(salt_b64).map_err(|e| e.to_string())?;
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
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
    let (nonce_bytes, cipher_text) = combined.split_at(NONCE_LEN);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| VaultDecryptError::Other(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, cipher_text)
        .map_err(|_| VaultDecryptError::DecryptFailed)
}
