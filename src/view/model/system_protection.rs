pub enum SystemProtectionAction {
    Check,
    #[cfg(target_os = "windows")]
    OpenSettings,
    SetEnabled(bool),
}

#[derive(Default)]
pub struct SystemProtectionDisplay {
    pub available: bool,
    pub check: Option<Result<bool, String>>,
    pub enabled: bool,
    pub action: Option<SystemProtectionAction>,
    pub error: Option<String>,
}
