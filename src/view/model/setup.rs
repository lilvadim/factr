use zeroize::Zeroizing;

pub enum SetupAction {
    Start,
    Complete,
    Cancel,
}

pub enum SetupScreen {
    Input(SetupInputDisplay),
    ConfirmRecovery(RecoveryConfirmationDisplay),
}

impl Default for SetupScreen {
    fn default() -> Self {
        Self::Input(SetupInputDisplay::default())
    }
}

pub struct SetupInputDisplay {
    pub legacy: bool,
    pub password: Zeroizing<String>,
    pub use_system: bool,
    pub can_create: bool,
    pub need_default_focus: bool,
}

impl Default for SetupInputDisplay {
    fn default() -> Self {
        Self {
            legacy: false,
            password: Default::default(),
            use_system: false,
            can_create: true,
            need_default_focus: true,
        }
    }
}

pub struct RecoveryConfirmationDisplay {
    pub key: Zeroizing<String>,
    pub saved: bool,
}

#[derive(Default)]
pub struct SetupDisplay {
    pub screen: SetupScreen,
    pub action: Option<SetupAction>,
    pub error: Option<String>,
}
