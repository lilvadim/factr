use zeroize::Zeroizing;

pub enum UnlockAction {
    Recovery,
    System,
}

pub struct UnlockDisplay {
    pub recovery_key: Zeroizing<String>,
    pub use_recovery_key: bool,
    pub need_default_focus: bool,
    pub action: Option<UnlockAction>,
    pub error: Option<String>,
}

impl Default for UnlockDisplay {
    fn default() -> Self {
        Self {
            recovery_key: Default::default(),
            use_recovery_key: false,
            need_default_focus: true,
            action: None,
            error: None,
        }
    }
}
