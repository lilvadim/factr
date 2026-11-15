use crate::view::model::unlock::{UnlockAction, UnlockDisplay};
use crate::{
    phosphor,
    view::model::system_protection::SystemProtectionDisplay,
    view::widget::{access_input, form_key},
};
use egui::{Frame, Response, Ui, Widget};
use rust_i18n::t;

pub struct UnlockForm<'a> {
    pub display: &'a mut UnlockDisplay,
    pub system: &'a SystemProtectionDisplay,
    pub busy: bool,
}

impl Widget for UnlockForm<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        let display = self.display;
        let system = self.system;
        let busy = self.busy;
        Frame::new()
            .inner_margin(25.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        ui.heading(format!("{} {}", phosphor::VAULT, t!("vault-locked")));
                        let needs_system_setup =
                            !system.system_protection_bound || !system.available;
                        if display.use_recovery_key || needs_system_setup {
                            ui.label(t!("access.system-restore-about"));
                            ui.strong(t!("access.restore-system-after-unlock"));
                        }
                        let (can_unlock, label, next) = if display.use_recovery_key {
                            (
                                !display.recovery_key.is_empty(),
                                t!("unlock-vault"),
                                UnlockAction::Recovery,
                            )
                        } else {
                            (
                                system.system_protection_bound && system.available,
                                t!("access.unlock-system"),
                                UnlockAction::System,
                            )
                        };
                        if ui
                            .add_enabled(can_unlock, egui::Button::new(label).selected(true))
                            .clicked()
                            || (can_unlock && form_key(ui, egui::Key::Enter))
                        {
                            display.action = Some(next);
                        }
                        if ui
                            .checkbox(&mut display.use_recovery_key, t!("access.use-recovery-key"))
                            .changed()
                        {
                            use zeroize::Zeroize;
                            display.recovery_key.zeroize();
                            display.need_default_focus = display.use_recovery_key;
                        }
                        if display.use_recovery_key {
                            access_input(
                                ui,
                                &mut display.recovery_key,
                                &mut display.need_default_focus,
                                busy,
                                "access.recovery-key",
                            );
                        }
                    });
                    if busy {
                        ui.spinner();
                    }
                    if let Some(error) = &display.error {
                        ui.colored_label(ui.visuals().error_fg_color, error);
                    }
                });
            })
            .response
    }
}
