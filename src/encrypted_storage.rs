use serde::{Deserialize, Serialize};
use totp_rs::Algorithm;

use crate::vault::{self};

const KEY_LEN: usize = 32;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedAccount {
    pub issuer: Option<String>,
    pub account_name: String,
    pub encrypted_secret_b64: String,
    pub algo: Algorithm,
    pub digits: usize,
    pub period: u64,
}

impl EncryptedAccount {
    pub fn encrypt_account(account: &vault::Account, key: &[u8; KEY_LEN]) -> Result<Self, String> {
        Ok(Self {
            issuer: account.totp.issuer.to_owned(),
            account_name: account.totp.account_name.to_owned(),
            encrypted_secret_b64: vault::encrypt_secret(&account.totp.secret, key)?,
            algo: account.totp.algorithm,
            digits: account.totp.digits,
            period: account.totp.step,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Storage {
    pub salt_b64: String,
    pub sealed_check: String,
    pub accounts: Vec<EncryptedAccount>,
}

impl Storage {
    pub const SEALED_CHECK: &[u8] = b"FACTR_AUTH_CHECK";

    pub fn encrypt_vault(vault: &vault::Vault) -> Result<Self, String> {
        let salt_b64 = vault.salt.to_string();
        let accounts: Result<Vec<EncryptedAccount>, String> = vault
            .accounts
            .iter()
            .map(|acc| EncryptedAccount::encrypt_account(acc, &vault.master_key))
            .collect();
        let accounts = accounts?;
        let sealed_check = vault::encrypt_secret(Self::SEALED_CHECK, &vault.master_key)?;
        Ok(Self {
            salt_b64,
            accounts,
            sealed_check,
        })
    }
}
