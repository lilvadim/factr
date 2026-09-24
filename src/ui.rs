use egui::{Frame, Label, RichText, Sense, Ui, UiBuilder, Widget, vec2};
use rust_i18n::t;

use crate::display::AccountDisplay;

pub const ACCOUNT_CARD_MIN_WIDTH: f32 = 150.0;
pub const ACCOUNT_CARD_MAX_WIDTH: f32 = 300.0;
pub const ACCOUNT_CARD_HEIGHT: f32 = 100.0;

pub fn account_ui(ui: &mut Ui, account: &AccountDisplay, width: f32) -> egui::Response {
    let response = ui
        .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
            let response = ui.response();
            let visuals = ui.style().interact(&response);

            let frame = Frame::canvas(ui.style())
                .fill(visuals.bg_fill)
                .stroke(visuals.bg_stroke)
                .inner_margin(ui.spacing().menu_margin);
            let content_size = vec2(width, ACCOUNT_CARD_HEIGHT) - frame.total_margin().sum();

            frame.show(ui, |ui| {
                ui.set_min_size(content_size);

                ui.vertical(|ui| {
                    if let Some(issuer) = account.issuer.as_ref() {
                        Label::new(RichText::new(issuer).heading())
                            .selectable(false)
                            .ui(ui);
                    }
                    Label::new(RichText::new(&account.account_name))
                        .selectable(false)
                        .ui(ui);
                    Label::new(RichText::new(&account.code).size(24.0).monospace())
                        .selectable(false)
                        .ui(ui);
                    Label::new(RichText::new(format!(
                        "{} {}",
                        account.remaining_secs,
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
