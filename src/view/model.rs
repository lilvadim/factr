use egui::ThemePreference;
use totp_rs::Algorithm;
use uuid::Uuid;

use crate::{
    config::{AccountSort, Config},
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
    pub id: Uuid,
    pub created_at: i64,
    pub modified_at: i64,
    pub custom_position: usize,
    pub issuer: Option<String>,
    pub account_name: String,
    pub code: String,
    pub remaining_secs: u64,
}

impl AccountDisplay {
    pub fn from_account(account: &Account) -> Result<Self, String> {
        let (code, remaining_secs) = account.current_state()?;
        Ok(Self {
            id: account.id,
            created_at: account.created_at,
            modified_at: account.modified_at,
            custom_position: account.custom_position,
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
pub struct AppDisplay {
    pub filter_search: String,
    pub password: String,
    pub setup_display: Option<SetupDisplay>,
    pub add_ui: bool,
    pub add_display: Option<AccountFieldsDisplay>,
    pub search_focus: bool,
    pub settings_ui: bool,
    pub settings_display: Option<SettingsDisplay>,
    pub edit_display: Option<EditDisplay>,
    pub sort: AccountSort,
}

pub(crate) struct EditDisplay {
    pub id: Uuid,
    pub input: AccountFieldsDisplay,
}

impl EditDisplay {
    pub fn from_account(account: &Account) -> Self {
        Self {
            id: account.id,
            input: AccountFieldsDisplay {
                manual: ManualInput {
                    issuer: account.totp.issuer.clone().unwrap_or_default(),
                    account_name: account.totp.account_name.clone(),
                    secret: account.totp.get_secret_base32(),
                },
                extra_input: true,
                manual_extra: Some(ManualInputExtra {
                    algo: account.totp.algorithm,
                    digits: account.totp.digits,
                    period: account.totp.step,
                }),
                ..Default::default()
            },
        }
    }
}

impl AccountFieldsDisplay {
    pub fn to_account(&self, position: usize) -> Result<Account, String> {
        if self.method == AddMethod::OtpAuthUrl {
            return Account::from_otp_auth_url(&self.otp_auth_url, position);
        }
        let issuer = (!self.manual.issuer.is_empty()).then(|| self.manual.issuer.clone());
        if self.extra_input
            && let Some(extra) = &self.manual_extra
        {
            Account::from_manual(
                issuer,
                self.manual.account_name.clone(),
                extra.algo,
                extra.digits,
                extra.period,
                self.manual.secret.clone(),
                position,
            )
        } else {
            Account::from_manual_with_defaults(
                issuer,
                self.manual.account_name.clone(),
                self.manual.secret.clone(),
                position,
            )
        }
    }
}

#[derive(Default)]
pub(crate) struct SetupDisplay {
    pub password: String,
    pub error: Option<String>,
}

#[derive(Default)]
pub(crate) struct AccountFieldsDisplay {
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
