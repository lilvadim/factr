use crate::phosphor;
use egui::{
    ComboBox, DragValue, Frame, Id, Key, Label, Response, RichText, Sense, TextEdit, Ui, UiBuilder,
    Widget, vec2,
};
use rust_i18n::t;
use totp_rs::Algorithm;

use crate::config::{AccountSort, SortField};
use crate::view::model::{
    AccountDisplay, AccountFieldsDisplay, AddMethod, ManualInput, ManualInputExtra,
    VaultAccessAction, VaultAccessDisplay, VaultAccessScreen,
};

pub struct VaultAccessForm<'a>(pub &'a mut VaultAccessDisplay);

impl Widget for VaultAccessForm<'_> {
    /// Renders the current setup, migration, or unlock step.
    fn ui(self, ui: &mut Ui) -> Response {
        let display = self.0;
        Frame::new()
            .inner_margin(25.0)
            .show(ui, |ui| {
                ui.add_enabled_ui(!display.busy, |ui| match display.screen {
                    VaultAccessScreen::Create | VaultAccessScreen::Legacy => {
                        let legacy = display.screen == VaultAccessScreen::Legacy;
                        ui.heading(t!(if legacy {
                            "access.migrate-title"
                        } else {
                            "setup.title"
                        }));
                        ui.label(t!("access.about"));
                        if legacy {
                            ui.label(t!("access.migrate-about"));
                            access_input(ui, display, "password");
                        }
                        system_choice(ui, display);
                        if ui
                            .add_enabled(
                                legacy || display.can_create,
                                egui::Button::new(t!("access.continue")).selected(true),
                            )
                            .clicked()
                            || ((legacy || display.can_create) && form_key(ui, egui::Key::Enter))
                        {
                            display.action = Some(VaultAccessAction::Prepare);
                        }
                    }
                    VaultAccessScreen::ConfirmRecovery => {
                        ui.heading(t!("access.recovery-title"));
                        ui.label(t!("access.recovery-about"));
                        ui.add(
                            Label::new(RichText::new(display.recovery_key.as_str()).monospace())
                                .selectable(true)
                                .wrap(),
                        );
                        ui.checkbox(&mut display.recovery_saved, t!("access.recovery-saved"));
                        ui.horizontal(|ui| {
                            if ui.button(t!("cancel")).clicked() || form_key(ui, egui::Key::Escape)
                            {
                                display.action = Some(VaultAccessAction::Cancel);
                            }
                            if ui
                                .add_enabled(
                                    display.recovery_saved,
                                    egui::Button::new(t!("save")).selected(true),
                                )
                                .clicked()
                                || (display.recovery_saved && form_key(ui, egui::Key::Enter))
                            {
                                display.action = Some(VaultAccessAction::Confirm);
                            }
                        });
                    }
                    VaultAccessScreen::Locked => {
                        ui.heading(format!("{} {}", phosphor::VAULT, t!("vault-locked")));
                        let can_unlock = if display.use_recovery_key {
                            !display.input.is_empty()
                        } else {
                            display.system_enabled
                        };
                        let label = if display.use_recovery_key || !display.system_enabled {
                            t!("unlock-vault")
                        } else {
                            t!("access.unlock-system")
                        };
                        if ui
                            .add_enabled(can_unlock, egui::Button::new(label).selected(true))
                            .clicked()
                            || (can_unlock && form_key(ui, egui::Key::Enter))
                        {
                            display.action = Some(if display.use_recovery_key {
                                VaultAccessAction::UnlockRecovery
                            } else {
                                VaultAccessAction::UnlockSystem
                            });
                        }
                        if ui
                            .checkbox(&mut display.use_recovery_key, t!("access.use-recovery-key"))
                            .changed()
                        {
                            use zeroize::Zeroize;
                            display.input.zeroize();
                            display.need_default_focus = display.use_recovery_key;
                        }
                        if display.use_recovery_key {
                            ui.label(t!("access.enter-recovery"));
                            access_input(ui, display, "access.recovery-key");
                            if !display.system_enabled {
                                system_choice(ui, display);
                            }
                        }
                    }
                });
                if display.busy {
                    ui.spinner();
                }
                if let Some(error) = &display.error {
                    ui.colored_label(ui.visuals().error_fg_color, error);
                }
            })
            .response
    }
}

/// Renders a secret input field with one-time default focus.
fn access_input(ui: &mut Ui, display: &mut VaultAccessDisplay, hint: &str) {
    let input = ui.add(
        TextEdit::singleline(&mut *display.input)
            .id(egui::Id::unique("vault-access-input"))
            .desired_width(ui.available_width())
            .password(true)
            .hint_text(t!(hint)),
    );
    if display.need_default_focus {
        input.request_focus();
        display.need_default_focus = false;
    }
}

/// Shows system protection availability and enrollment options.
fn system_choice(ui: &mut Ui, display: &mut VaultAccessDisplay) {
    if display.system_available {
        ui.checkbox(&mut display.use_system, t!("access.enable-system"));
    } else {
        ui.label(t!("access.system-unavailable"));
    }
    #[cfg(target_os = "linux")]
    linux_security_warning(ui);
}

#[cfg(target_os = "linux")]
/// Explains the limits of system keyring protection on Linux.
fn linux_security_warning(ui: &mut Ui) {
    let title =
        RichText::new(t!("access.linux-security-warning-title")).color(ui.visuals().warn_fg_color);
    egui::CollapsingHeader::new(title)
        .id_salt("linux-security-warning")
        .default_open(false)
        .show(ui, |ui| {
            ui.label(t!("access.linux-security-warning"));
        });
}

pub struct SystemProtectionControl<'a>(pub &'a mut VaultAccessDisplay);

impl Widget for SystemProtectionControl<'_> {
    /// Renders the system protection setting and queues changes.
    fn ui(self, ui: &mut Ui) -> Response {
        let display = self.0;
        let mut enabled = display.system_enabled;
        let response = ui.add_enabled(
            display.system_available && !display.busy,
            egui::Checkbox::new(&mut enabled, t!("access.enable-system")),
        );
        if response.changed() {
            display.action = Some(VaultAccessAction::SetSystemProtection(enabled));
        }
        if let Some(error) = &display.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        #[cfg(target_os = "linux")]
        linux_security_warning(ui);
        response
    }
}

pub struct AccountSortControl<'a>(pub &'a mut AccountSort);

pub struct InnerWindowHeader<'a> {
    title: &'a str,
}

impl<'a> InnerWindowHeader<'a> {
    pub fn new(title: &'a str) -> Self {
        Self { title }
    }
}

impl Widget for InnerWindowHeader<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        let close = ui
            .horizontal(|ui| {
                #[cfg(target_os = "macos")]
                {
                    let close =
                        ui.add(egui::Button::new(RichText::new(phosphor::X_CIRCLE)).frame(false));
                    ui.add(Label::new(RichText::new(self.title).strong()).selectable(false));
                    close
                }
                #[cfg(not(target_os = "macos"))]
                {
                    ui.add(Label::new(RichText::new(self.title).strong()).selectable(false));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(egui::Button::new(RichText::new(phosphor::X_SQUARE)).frame(false))
                    })
                    .inner
                }
            })
            .inner;
        ui.separator();
        ui.add_space(ui.spacing().item_spacing.y);
        close
    }
}

impl AccountSortControl<'_> {
    pub fn width(&self, ui: &mut Ui) -> f32 {
        let mut sort = *self.0;
        let mut sizing_ui = ui.new_child(
            UiBuilder::new()
                .id_salt("sort-control-size")
                .layout(egui::Layout::right_to_left(egui::Align::Center))
                .sizing_pass()
                .invisible(),
        );
        sizing_ui.add(AccountSortControl(&mut sort)).rect.width()
    }
}

impl Widget for AccountSortControl<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        let sort = self.0;
        let label = |field| match field {
            SortField::Name => t!("sort.name"),
            SortField::Username => t!("sort.username"),
            SortField::FirstAdded => t!("sort.first-added"),
            SortField::LastModified => t!("sort.last-modified"),
        };
        let mut controls = None;
        let mut changed = false;
        let right_to_left = ui.layout().main_dir() == egui::Direction::RightToLeft;
        let checkbox = |ui: &mut Ui, sort: &mut AccountSort| {
            let text = if sort.enabled {
                t!("sort.by")
            } else {
                t!("sort.enable")
            };
            ui.checkbox(&mut sort.enabled, text)
        };
        let direction = |ui: &mut Ui, sort: &mut AccountSort| {
            let mut response = ui.button(if sort.descending {
                phosphor::ARROW_DOWN_RIGHT
            } else {
                phosphor::ARROW_UP_RIGHT
            });
            if response.clicked() {
                sort.descending = !sort.descending;
                response.mark_changed();
            }
            response
        };
        let first = if right_to_left {
            None
        } else {
            Some(checkbox(ui, sort))
        };
        if sort.enabled {
            let leading = if right_to_left {
                Some(direction(ui, sort))
            } else {
                None
            };
            let field = ComboBox::from_id_salt("account-sort")
                .selected_text(label(sort.field))
                .show_ui(ui, |ui| {
                    for field in [
                        SortField::Name,
                        SortField::Username,
                        SortField::FirstAdded,
                        SortField::LastModified,
                    ] {
                        changed |= ui
                            .selectable_value(&mut sort.field, field, label(field))
                            .changed();
                    }
                });
            let direction = leading.unwrap_or_else(|| direction(ui, sort));
            controls = Some(direction | field.response);
        }
        let checkbox = first.unwrap_or_else(|| checkbox(ui, sort));
        let mut response = match controls {
            Some(controls) => checkbox | controls,
            None => checkbox,
        };
        if changed {
            response.mark_changed();
        }
        response
    }
}

pub struct AccountCodeCard<'a> {
    account: &'a AccountDisplay,
    width: f32,
    interaction_id: Option<Id>,
}

impl<'a> AccountCodeCard<'a> {
    pub const MIN_WIDTH: f32 = 150.0;
    pub const MAX_WIDTH: f32 = 300.0;
    pub const HEIGHT: f32 = 100.0;

    pub fn new(account: &'a AccountDisplay, width: f32, interaction_id: Option<Id>) -> Self {
        Self {
            account,
            width,
            interaction_id,
        }
    }
}

impl Widget for AccountCodeCard<'_> {
    fn ui(self, ui: &mut Ui) -> egui::Response {
        let response = ui
            .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
                let response = self
                    .interaction_id
                    .and_then(|id| ui.ctx().read_response(id))
                    .unwrap_or_else(|| ui.response());
                let visuals = *ui.style().interact(&response);

                let frame = Frame::canvas(ui.style())
                    .stroke(egui::Stroke::NONE)
                    .inner_margin(ui.spacing().menu_margin);
                let content_size = vec2(self.width, Self::HEIGHT) - frame.total_margin().sum();

                let mut prepared = frame.begin(ui);
                {
                    let ui = &mut prepared.content_ui;
                    ui.set_min_size(content_size);

                    ui.vertical(|ui| {
                        if let Some(issuer) = self.account.issuer.as_ref() {
                            Label::new(RichText::new(issuer).heading())
                                .selectable(false)
                                .ui(ui);
                        }
                        Label::new(RichText::new(&self.account.account_name))
                            .selectable(false)
                            .ui(ui);
                        Label::new(RichText::new(&self.account.code).size(24.0).monospace())
                            .selectable(false)
                            .ui(ui);
                        Label::new(RichText::new(format!(
                            "{} {}",
                            self.account.remaining_secs,
                            t!("sec")
                        )))
                        .selectable(false)
                        .ui(ui);
                    });
                }
                prepared.allocate_space(ui);
                prepared.frame = prepared
                    .frame
                    .inner_margin(
                        egui::epaint::MarginF32::from(frame.inner_margin) + visuals.expansion
                            - visuals.bg_stroke.width,
                    )
                    .outer_margin(-visuals.expansion)
                    .fill(visuals.bg_fill)
                    .stroke(visuals.bg_stroke);
                prepared.paint(ui);
            })
            .response;
        ui.ctx().request_repaint_after_secs(1.0);
        response
    }
}

pub(crate) struct AccountInputForm<'a> {
    manual: &'a mut ManualInput,
    extra_input: &'a mut bool,
    extra: &'a mut Option<ManualInputExtra>,
}

impl<'a> AccountInputForm<'a> {
    pub fn new(
        manual: &'a mut ManualInput,
        extra_input: &'a mut bool,
        extra: &'a mut Option<ManualInputExtra>,
    ) -> Self {
        Self {
            manual,
            extra_input,
            extra,
        }
    }
}

impl Widget for AccountInputForm<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        let Self {
            manual,
            extra_input,
            extra,
        } = self;
        ui.scope(|ui| {
            ui.horizontal(|ui| {
                ui.label(t!("account.issuer"));
                TextEdit::singleline(&mut manual.issuer)
                    .hint_text(t!("account.issuer"))
                    .ui(ui);
            });
            ui.horizontal(|ui| {
                ui.label(t!("account.name"));
                TextEdit::singleline(&mut manual.account_name)
                    .hint_text(t!("account.name"))
                    .ui(ui);
            });
            ui.horizontal(|ui| {
                ui.label(t!("account.secret"));
                TextEdit::singleline(&mut manual.secret)
                    .hint_text(t!("account.secret"))
                    .ui(ui);
            });
            ui.checkbox(extra_input, format!("{}...", t!("add.additional")));
            if *extra_input {
                let mut extra_input = extra.get_or_insert_default();
                if ui.button(t!("add.restore-defaults")).clicked() {
                    extra_input = extra.insert(ManualInputExtra::default());
                }
                ui.horizontal(|ui| {
                    ui.label(t!("account.algorithm"));
                    ComboBox::from_id_salt("manual_extra.algo")
                        .selected_text(extra_input.algo.to_string())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut extra_input.algo,
                                Algorithm::SHA1,
                                Algorithm::SHA1.to_string(),
                            );
                            ui.selectable_value(
                                &mut extra_input.algo,
                                Algorithm::SHA256,
                                Algorithm::SHA256.to_string(),
                            );
                            ui.selectable_value(
                                &mut extra_input.algo,
                                Algorithm::SHA512,
                                Algorithm::SHA512.to_string(),
                            );
                        });
                });
                ui.horizontal(|ui| {
                    ui.label(t!("account.digits"));
                    DragValue::new(&mut extra_input.digits).range(6..=8).ui(ui);
                });
                ui.horizontal(|ui| {
                    ui.label(t!("account.period"));
                    DragValue::new(&mut extra_input.period)
                        .range(5..=300)
                        .ui(ui);
                });
            }
        })
        .response
    }
}

/// Consumes a form shortcut only when its UI layer is active.
pub(crate) fn form_key(ui: &mut Ui, key: Key) -> bool {
    let layer = ui.layer_id();
    let focused_layer = ui
        .memory(|memory| memory.focused())
        .and_then(|id| ui.ctx().read_response(id))
        .map(|response| response.layer_id);
    if focused_layer.is_some_and(|focused| focused != layer) {
        return false;
    }
    let is_active = ui.memory(|memory| {
        memory
            .layer_ids()
            .filter(|id| {
                memory.areas().is_visible(id)
                    && matches!(id.order, egui::Order::Middle | egui::Order::Foreground)
            })
            .last()
            .is_none_or(|id| id == layer)
    });
    is_active && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, key))
}

pub(crate) struct AccountAddForm<'a> {
    display: &'a mut AccountFieldsDisplay,
}

impl<'a> AccountAddForm<'a> {
    pub fn new(display: &'a mut AccountFieldsDisplay) -> Self {
        Self { display }
    }
}

impl Widget for AccountAddForm<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        let method_name = |method: &AddMethod| match method {
            AddMethod::OtpAuthUrl => "OTP Auth URL".to_string(),
            AddMethod::ManualInput => t!("add.manual-input").to_string(),
        };
        ui.scope(|ui| {
            ComboBox::from_label(t!("add.method"))
                .selected_text(method_name(&self.display.method))
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.display.method,
                        AddMethod::OtpAuthUrl,
                        method_name(&AddMethod::OtpAuthUrl),
                    );
                    ui.selectable_value(
                        &mut self.display.method,
                        AddMethod::ManualInput,
                        method_name(&AddMethod::ManualInput),
                    );
                });
            match self.display.method {
                AddMethod::OtpAuthUrl => {
                    TextEdit::singleline(&mut self.display.otp_auth_url)
                        .hint_text(method_name(&self.display.method))
                        .show(ui);
                }
                AddMethod::ManualInput => {
                    ui.add(AccountInputForm::new(
                        &mut self.display.manual,
                        &mut self.display.extra_input,
                        &mut self.display.manual_extra,
                    ));
                }
            }
        })
        .response
    }
}
