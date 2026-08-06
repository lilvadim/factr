use eframe::Renderer;

use crate::app::FactrApp;

mod app;
mod config;
mod display;
mod encrypted_storage;
mod ui;
mod vault;

rust_i18n::i18n!("locales", fallback = "en");

fn icon() -> egui::IconData {
    let image = image::load_from_memory(include_bytes!("../assets/icon/factr_icon.png"))
        .unwrap()
        .to_rgba8();
    let size = [image.width() as _, image.height() as _];
    let rgba = image.into_raw();
    egui::IconData {
        rgba,
        width: size[0],
        height: size[1],
    }
}

fn main() -> eframe::Result {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).
    let viewport = egui::ViewportBuilder::default()
        .with_app_id(config::APP_NAME)
        .with_title("Factr.")
        .with_icon(icon());
    #[cfg(target_os = "macos")]
    let viewport = viewport.with_titlebar_shown(false).with_title_shown(false);
    let options = eframe::NativeOptions {
        viewport,
        persist_window: true,
        renderer: Renderer::Wgpu,
        ..Default::default()
    };

    eframe::run_native(
        config::APP_NAME,
        options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            FactrApp::setup_fonts(&cc.egui_ctx);
            Ok(Box::new(FactrApp::init(
                config::read_from_dot_config()
                    .inspect_err(|e| eprintln!("{}", e))
                    .unwrap_or_default(),
            )))
        }),
    )
}
