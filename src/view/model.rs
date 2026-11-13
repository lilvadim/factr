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
            issuer: account.totp.issuer().map(str::to_owned),
            account_name: account.totp.account_name().to_owned(),
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

pub struct AppDisplay {
    pub filter_search: String,
    pub need_default_focus: bool,
    pub add_ui: bool,
    pub add_display: Option<AccountFieldsDisplay>,
    pub settings_ui: bool,
    pub settings_display: Option<SettingsDisplay>,
    pub edit_display: Option<EditDisplay>,
    pub sort: AccountSort,
}

impl Default for AppDisplay {
    fn default() -> Self {
        Self {
            filter_search: Default::default(),
            need_default_focus: true,
            add_ui: Default::default(),
            add_display: Default::default(),
            settings_ui: Default::default(),
            settings_display: Default::default(),
            edit_display: Default::default(),
            sort: Default::default(),
        }
    }
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
                    issuer: account.totp.issuer().unwrap_or_default().to_owned(),
                    account_name: account.totp.account_name().to_owned(),
                    secret: account.totp.secret().to_base32(),
                },
                extra_input: true,
                manual_extra: Some(ManualInputExtra {
                    algo: account.totp.algorithm(),
                    digits: account.totp.digits().into(),
                    period: account.totp.step(),
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

#[derive(PartialEq, Eq)]
pub enum VaultAccessScreen {
    Create,
    Legacy,
    Locked,
    ConfirmRecovery,
}

pub enum VaultAccessAction {
    Prepare,
    Confirm,
    Cancel,
    UnlockRecovery,
    UnlockSystem,
    SetSystemProtection(bool),
}

pub struct VaultAccessDisplay {
    pub screen: VaultAccessScreen,
    pub input: zeroize::Zeroizing<String>,
    pub recovery_key: zeroize::Zeroizing<String>,
    pub recovery_saved: bool,
    pub use_recovery_key: bool,
    pub system_available: bool,
    pub system_enabled: bool,
    pub use_system: bool,
    pub busy: bool,
    pub can_create: bool,
    pub need_default_focus: bool,
    pub error: Option<String>,
    pub action: Option<VaultAccessAction>,
}

impl Default for VaultAccessDisplay {
    /// Initializes the unlock form with the available system protection.
    fn default() -> Self {
        let available = crate::system_protection::available();
        Self {
            screen: VaultAccessScreen::Create,
            input: Default::default(),
            recovery_key: Default::default(),
            recovery_saved: false,
            use_recovery_key: false,
            system_available: available,
            system_enabled: false,
            use_system: available,
            busy: false,
            can_create: true,
            need_default_focus: true,
            error: None,
            action: None,
        }
    }
}

impl VaultAccessDisplay {
    /// Wipes transient secrets and resets pending confirmation state.
    pub fn clear_secrets(&mut self) {
        use zeroize::Zeroize;
        self.input.zeroize();
        self.recovery_key.zeroize();
        self.recovery_saved = false;
        self.use_recovery_key = false;
        self.action = None;
    }
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
