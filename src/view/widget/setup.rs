use super::system_protection::SystemProtectionSetupWizard;
use crate::view::model::setup::{SetupAction, SetupDisplay, SetupScreen};
use crate::{
    view::model::system_protection::SystemProtectionDisplay,
    view::widget::{access_input, form_key},
};
use egui::{Frame, Label, Response, RichText, Ui, Widget};
use rust_i18n::t;

pub struct SetupForm<'a> {
    pub display: &'a mut SetupDisplay,
    pub system: &'a mut SystemProtectionDisplay,
    pub busy: bool,
}

impl Widget for SetupForm<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        let SetupDisplay {
            screen,
            action,
            error,
        } = self.display;
        let system = self.system;
        let busy = self.busy;
        Frame::new()
            .inner_margin(25.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_enabled_ui(!busy, |ui| match screen {
                        SetupScreen::Input(input) => {
                            if input.legacy {
                                ui.heading(t!("access.migrate-title"));
                                ui.label(t!("access.migrate-about"));
                                access_input(
                                    ui,
                                    &mut input.password,
                                    &mut input.need_default_focus,
                                    busy,
                                    "password",
                                );
                            } else {
                                ui.heading(t!("setup.title"));
                            }
                            ui.add(SystemProtectionSetupWizard {
                                display: system,
                                use_system: &mut input.use_system,
                                busy,
                            });
                            let can_continue = input.legacy || input.can_create;
                            let continue_button = ui.add_enabled(
                                can_continue,
                                egui::Button::new(t!("access.continue")).selected(true),
                            );
                            let submit = can_continue && form_key(ui, egui::Key::Enter);
                            if continue_button.clicked() || submit {
                                *action = Some(SetupAction::Start);
                            }
                        }
                        SetupScreen::ConfirmRecovery(confirmation) => {
                            ui.heading(t!("access.recovery-title"));
                            ui.label(t!("access.recovery-about"));
                            ui.add(
                                Label::new(RichText::new(confirmation.key.as_str()).monospace())
                                    .selectable(true)
                                    .wrap(),
                            );
                            ui.checkbox(&mut confirmation.saved, t!("access.recovery-saved"));
                            ui.horizontal(|ui| {
                                if ui.button(t!("cancel")).clicked()
                                    || form_key(ui, egui::Key::Escape)
                                {
                                    *action = Some(SetupAction::Cancel);
                                }
                                if ui
                                    .add_enabled(
                                        confirmation.saved,
                                        egui::Button::new(t!("save")).selected(true),
                                    )
                                    .clicked()
                                    || (confirmation.saved && form_key(ui, egui::Key::Enter))
                                {
                                    *action = Some(SetupAction::Complete);
                                }
                            });
                        }
                    });
                    if busy {
                        ui.spinner();
                    }
                    if let Some(error) = error {
                        ui.colored_label(ui.visuals().error_fg_color, error);
                    }
                });
            })
            .response
    }
}
