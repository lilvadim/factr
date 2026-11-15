use crate::view::model::system_protection::{SystemProtectionAction, SystemProtectionDisplay};
use egui::{Color32, Response, Ui, Widget};
use rust_i18n::t;

const SYSTEM_PROTECTION_GUIDE: &str =
    "https://github.com/lilvadim/factr/blob/main/user_guide/SYSTEM_PROTECTION_GUIDE.md";

/// Explains the two unlock methods and offers platform setup and a fresh check.
fn system_protection_setup_info(
    ui: &mut Ui,
    display: &SystemProtectionDisplay,
    busy: bool,
) -> Option<SystemProtectionAction> {
    let mut action = None;
    ui.label(t!("access.security-intro"));
    ui.strong(t!("access.security-system-title"));
    ui.label(t!("access.security-system-about"));
    ui.strong(t!("access.security-recovery-title"));
    ui.label(t!("access.security-recovery-about"));
    ui.label(t!("access.security-recovery-only"));
    ui.add_space(ui.spacing().item_spacing.y);

    if display.available {
        let color = if ui.visuals().dark_mode {
            Color32::LIGHT_GREEN
        } else {
            Color32::DARK_GREEN
        };
        ui.colored_label(
            color,
            t!(if cfg!(target_os = "windows") {
                "access.windows-ready"
            } else {
                "access.system-ready"
            }),
        );
    } else {
        ui.label(t!(if cfg!(target_os = "windows") {
            "access.windows-setup"
        } else if cfg!(target_os = "linux") {
            "access.linux-setup"
        } else {
            "access.system-unavailable"
        }));
    }
    ui.horizontal_wrapped(|ui| {
        #[cfg(target_os = "windows")]
        if !display.available
            && ui
                .add_enabled(!busy, egui::Link::new(t!("access.open-signin-settings")))
                .clicked()
        {
            action = Some(SystemProtectionAction::OpenSettings);
        }
        ui.hyperlink_to(t!("access.system-guide"), SYSTEM_PROTECTION_GUIDE);
    });
    if !display.available {
        let label = t!("access.check-again");
        if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
            action = Some(SystemProtectionAction::Check);
        }
    }
    match &display.check {
        Some(Ok(false)) => {
            ui.strong(t!(if cfg!(target_os = "windows") {
                "access.windows-not-ready"
            } else {
                "access.system-not-ready"
            }));
        }
        Some(Err(error)) => {
            ui.strong(t!("access.system-check-failed"));
            ui.label(error);
        }
        _ => {}
    }
    action
}

pub struct SystemProtectionSetupWizard<'a> {
    pub display: &'a mut SystemProtectionDisplay,
    pub use_system: &'a mut bool,
    pub busy: bool,
}

impl Widget for SystemProtectionSetupWizard<'_> {
    /// Shows enrollment options while setting up a vault.
    fn ui(self, ui: &mut Ui) -> Response {
        let display = self.display;
        ui.strong(t!("access.security-title"));
        if let Some(action) = system_protection_setup_info(ui, display, self.busy) {
            display.action = Some(action);
        }
        let response = ui.add_enabled(
            display.available && !self.busy,
            egui::Checkbox::new(self.use_system, t!("access.enable-system")),
        );
        if let Some(error) = &display.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        #[cfg(target_os = "linux")]
        linux_security_warning(ui);
        response
    }
}

#[cfg(target_os = "linux")]
/// Explains the limits of system keyring protection on Linux.
fn linux_security_warning(ui: &mut Ui) {
    let title = egui::RichText::new(t!("access.linux-security-warning-title"))
        .color(ui.visuals().warn_fg_color);
    egui::CollapsingHeader::new(title)
        .id_salt("linux-security-warning")
        .default_open(false)
        .show(ui, |ui| {
            ui.label(t!("access.linux-security-warning"));
        });
}

pub struct SystemProtectionControl<'a> {
    pub display: &'a mut SystemProtectionDisplay,
    pub busy: bool,
}

impl Widget for SystemProtectionControl<'_> {
    /// Renders the shared protection status and queues requested changes.
    fn ui(self, ui: &mut Ui) -> Response {
        let display = self.display;
        if display.enabled {
            egui::CollapsingHeader::new(t!("access.security-title"))
                .id_salt("vault-security")
                .default_open(false)
                .show(ui, |ui| {
                    if let Some(action) = system_protection_setup_info(ui, display, self.busy) {
                        display.action = Some(action);
                    }
                    #[cfg(target_os = "linux")]
                    linux_security_warning(ui);
                });
        } else {
            ui.strong(t!("access.security-title"));
            if let Some(action) = system_protection_setup_info(ui, display, self.busy) {
                display.action = Some(action);
            }
        }
        let mut enabled = display.enabled;
        let response = ui.add_enabled(
            display.available && !self.busy,
            egui::Checkbox::new(&mut enabled, t!("access.enable-system")),
        );
        if response.changed() {
            display.action = Some(SystemProtectionAction::SetEnabled(enabled));
        }
        if let Some(error) = &display.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        #[cfg(target_os = "linux")]
        if !display.enabled {
            linux_security_warning(ui);
        }
        response
    }
}
