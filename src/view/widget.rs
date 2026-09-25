use egui::{
    ComboBox, DragValue, Frame, Id, Label, Response, RichText, Sense, TextEdit, Ui, UiBuilder,
    Widget, vec2,
};
use rust_i18n::t;
use totp_rs::Algorithm;

use crate::view::model::{AccountDisplay, AddDisplay, AddMethod, ManualInput, ManualInputExtra};

pub struct AccountCodeCard<'a> {
    account: &'a AccountDisplay,
    width: f32,
}

impl<'a> AccountCodeCard<'a> {
    pub const MIN_WIDTH: f32 = 150.0;
    pub const MAX_WIDTH: f32 = 300.0;
    pub const HEIGHT: f32 = 100.0;

    pub fn new(account: &'a AccountDisplay, width: f32) -> Self {
        Self { account, width }
    }
}

impl Widget for AccountCodeCard<'_> {
    fn ui(self, ui: &mut Ui) -> egui::Response {
        let response = ui
            .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
                let response = ui.response();
                let visuals = ui.style().interact(&response);

                let frame = Frame::canvas(ui.style())
                    .fill(visuals.bg_fill)
                    .stroke(visuals.bg_stroke)
                    .inner_margin(ui.spacing().menu_margin);
                let content_size = vec2(self.width, Self::HEIGHT) - frame.total_margin().sum();

                frame.show(ui, |ui| {
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
                });
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
                    ComboBox::from_id_salt(Id::new("manual_extra.algo"))
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

pub(crate) struct AccountAddForm<'a> {
    display: &'a mut AddDisplay,
}

impl<'a> AccountAddForm<'a> {
    pub fn new(display: &'a mut AddDisplay) -> Self {
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
