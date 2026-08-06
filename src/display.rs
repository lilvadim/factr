/// Displayable Data (View Model)
use crate::{
    config::Config,
    vault::{Account, Vault},
};

pub struct VaultDisplay {
    pub accounts: Vec<AccountDisplay>,
}

impl VaultDisplay {
    pub fn from_vault(vault: &Vault) -> Result<VaultDisplay, String> {
        let accounts: Result<Vec<AccountDisplay>, String> = vault
            .accounts
            .iter()
            .map(AccountDisplay::from_account)
            .collect();
        let accounts = accounts?;
        Ok(Self { accounts })
    }
}

pub struct AccountDisplay {
    pub issuer: Option<String>,
    pub account_name: String,
    pub code: String,
    pub remaining_secs: u64,
}

impl AccountDisplay {
    pub fn from_account(account: &Account) -> Result<Self, String> {
        let (code, remaining_secs) = account.current_state()?;
        Ok(Self {
            issuer: account.totp.issuer.to_owned(),
            account_name: account.totp.account_name.to_owned(),
            code,
            remaining_secs,
        })
    }
}

pub struct SettingsDisplay {
    pub close_after_copy: bool,
    pub always_on_top: bool,
    pub toolbar_labels: bool,
}

impl SettingsDisplay {
    pub fn from_config(config: &Config) -> Self {
        Self {
            close_after_copy: config.close_after_copy,
            always_on_top: config.always_on_top,
            toolbar_labels: config.toolbar_labels,
        }
    }
}
