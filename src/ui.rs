use egui::{Frame, Label, RichText, Sense, Ui, UiBuilder, Widget};

use crate::display::AccountDisplay;

pub fn account_ui(ui: &mut Ui, account: &AccountDisplay) -> egui::Response {
    let response = ui
        .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
            let response = ui.response();
            let visuals = ui.style().interact(&response);

            Frame::canvas(ui.style())
                .fill(visuals.bg_fill)
                .stroke(visuals.bg_stroke)
                .inner_margin(ui.spacing().menu_margin)
                .show(ui, |ui| {
                    ui.set_min_width(150.0);
                    ui.set_min_height(100.0);

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
                            "{}s remains",
                            account.remaining_secs
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
