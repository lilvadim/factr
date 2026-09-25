use egui::ThemePreference;
use totp_rs::Algorithm;

use crate::{
    config::Config,
    vault::{self, Account, Vault},
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
    pub theme: ThemePreference,
}

impl SettingsDisplay {
    pub fn from_config(config: &Config) -> Self {
        Self {
            close_after_copy: config.close_after_copy,
            always_on_top: config.always_on_top,
            toolbar_labels: config.toolbar_labels,
            theme: config.theme,
        }
    }
}

#[derive(Default)]
pub(crate) struct AppDisplay {
    pub filter_search: String,
    pub password: String,
    pub setup_display: Option<SetupDisplay>,
    pub add_ui: bool,
    pub add_display: Option<AddDisplay>,
    pub search_focus: bool,
    pub settings_ui: bool,
    pub settings_display: Option<SettingsDisplay>,
}

#[derive(Default)]
pub(crate) struct SetupDisplay {
    pub password: String,
    pub error: Option<String>,
}

#[derive(Default)]
pub(crate) struct AddDisplay {
    pub method: AddMethod,
    pub otp_auth_url: String,
    pub manual: ManualInput,
    pub extra_input: bool,
    pub manual_extra: Option<ManualInputExtra>,
    pub error: Option<String>,
}

#[derive(PartialEq, Eq, Default)]
pub(crate) enum AddMethod {
    OtpAuthUrl,
    #[default]
    ManualInput,
}

#[derive(Default)]
pub(crate) struct ManualInput {
    pub issuer: String,
    pub account_name: String,
    pub secret: String,
}

pub(crate) struct ManualInputExtra {
    pub algo: Algorithm,
    pub period: u64,
    pub digits: usize,
}

impl Default for ManualInputExtra {
    fn default() -> Self {
        Self {
            algo: vault::DEFAULT_ALGO,
            period: vault::DEFAULT_PERIOD,
            digits: vault::DEFAULT_DIGITS,
        }
    }
}
