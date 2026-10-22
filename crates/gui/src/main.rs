use eframe::egui;
use omnidecomp_gui::App;
use std::path::PathBuf;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 800.0]).with_title("OmniDecomp"),
        ..Default::default()
    };
    let initial = std::env::args_os().nth(1).map(PathBuf::from);
    eframe::run_native("OmniDecomp", options, Box::new(move |cc| Ok(Box::new(App::new(&cc.egui_ctx, initial)))))
}
