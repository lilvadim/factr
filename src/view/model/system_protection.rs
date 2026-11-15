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
    pub system_protection_bound: bool,
    pub pending_user_enabled: Option<bool>,
    pub action: Option<SystemProtectionAction>,
    pub error: Option<String>,
}

impl SystemProtectionDisplay {
    /// Returns the pending user choice or the saved protection binding.
    pub fn system_protection_user_choice(&self) -> bool {
        self.pending_user_enabled
            .unwrap_or(self.system_protection_bound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_choice_prefers_pending_changes_over_the_saved_binding() {
        let mut display = SystemProtectionDisplay {
            system_protection_bound: true,
            ..Default::default()
        };
        assert!(display.system_protection_user_choice());
        display.pending_user_enabled = Some(false);
        assert!(!display.system_protection_user_choice());
        display.system_protection_bound = false;
        display.pending_user_enabled = Some(true);
        assert!(display.system_protection_user_choice());
        display.pending_user_enabled = None;
        assert!(!display.system_protection_user_choice());
    }
}
