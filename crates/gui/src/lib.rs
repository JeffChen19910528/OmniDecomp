//! Desktop front end (library part, so the UI can be driven by tests). All analysis goes through `omnidecomp-viewmodel` (and from there the application
//! layer); this file only draws. Text from analyzed files is shown as plain labels, never as markup, and
//! the input file is never executed or loaded.

mod cjk;
mod i18n;
mod appearance;
mod loading;
mod panels;
mod plugin_ui;
mod widgets;

use eframe::egui::{self};
use omnidecomp_viewmodel::graph::GraphLayout;
use omnidecomp_viewmodel::{
    Locations, Hit, Loaded, Scope, Settings,
    Task,
};
pub use i18n::Lang;
use i18n::tr;
pub use loading::FilePicker;
use loading::native_picker;
use plugin_ui::PluginUi;
use widgets::sorted_rows;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LeftTab {
    Info,
    Functions,
    Symbols,
    Strings,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CenterTab {
    Disasm,
    Cfg,
    Calls,
    Decompile,
    Plugins,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BottomTab {
    Search,
    Xrefs,
    Log,
}

/// A laid-out graph and what it was built for, so it is rebuilt only when the question changes.
struct GraphState {
    key: (CenterTab, u64, usize),
    layout: Result<GraphLayout, String>,
}

pub struct App {
    settings: Settings,
    center: CenterTab,
    graph: Option<GraphState>,
    call_depth: usize,
    picker: FilePicker,
    pl: PluginUi,
    lang: Lang,
    /// Font that can draw Traditional Chinese, if the system has one.
    cjk: Option<(PathBuf, u32)>,
    applied_lang: Option<Lang>,
    prefs_path: Option<PathBuf>,
    pending_pick: Option<Receiver<Option<PathBuf>>>,
    path_input: String,
    task: Option<Task>,
    loaded: Option<Loaded>,
    error: Option<String>,
    log: Vec<String>,
    left: LeftTab,
    bottom: BottomTab,
    filter: String,
    query: String,
    scope: Scope,
    results: Vec<Hit>,
    selected: Option<u64>,
    /// Instruction row to scroll into view on the next frame.
    jump_row: Option<usize>,
    hex_offset: u64,
    applied: Option<Settings>,
}

impl App {
    pub fn new(ctx: &egui::Context, initial: Option<PathBuf>) -> Self {
        let plugins = Locations::resolve(None, None);
        // First start: follow the system locale; afterwards the saved choice wins.
        let saved = i18n::load_pref(i18n::prefs_path(plugins.state.as_deref()).as_deref());
        let mut app = Self::with_plugins(ctx, None, plugins);
        if saved.is_none() {
            app.lang = if Lang::from_env() == Lang::ZhTw && app.cjk.is_some() { Lang::ZhTw } else { Lang::En };
        }
        if let Some(p) = initial {
            app.path_input = p.to_string_lossy().into_owned();
            app.open(&p, ctx);
        }
        app
    }

    /// Like `new`, with explicit plugin folder and state file (tests use temporary ones).
    pub fn with_plugins(ctx: &egui::Context, initial: Option<PathBuf>, plugins: Locations) -> Self {
        let prefs_path = i18n::prefs_path(plugins.state.as_deref());
        let cjk = cjk::find();
        // Chinese needs a font; without one the saved choice cannot be honoured.
        let lang = i18n::load_pref(prefs_path.as_deref()).filter(|l| *l == Lang::En || cjk.is_some()).unwrap_or(Lang::En);
        let mut app = Self {
            settings: Settings::default(),
            center: CenterTab::Disasm,
            graph: None,
            call_depth: 1,
            picker: native_picker(),
            pl: PluginUi::new(plugins),
            lang,
            cjk,
            applied_lang: None,
            prefs_path,
            pending_pick: None,
            path_input: initial.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
            task: None,
            loaded: None,
            error: None,
            log: vec![tr(lang, "static analysis only: files are never executed").to_string()],
            left: LeftTab::Info,
            bottom: BottomTab::Search,
            filter: String::new(),
            query: String::new(),
            scope: Scope::All,
            results: Vec::new(),
            selected: None,
            jump_row: None,
            hex_offset: 0,
            applied: None,
        };
        if let Some(p) = initial {
            app.open(&p, ctx);
        }
        app
    }

    fn goto(&mut self, addr: u64) {
        let Some(l) = &self.loaded else { return };
        if let Some(i) = l.instruction_at_or_after(addr) {
            self.jump_row = Some(self.row_of(l, i));
            self.select(addr);
        } else if let Some(off) = l.file_offset_of(addr) {
            self.hex_offset = off;
        }
    }

    fn row_of(&self, l: &Loaded, instruction_index: usize) -> usize {
        // The list is drawn in address order, so the row is the rank of this instruction's address.
        let ins = l.instructions();
        let addr = ins[instruction_index].address;
        sorted_rows(l).partition_point(|i| ins[*i].address < addr)
    }

    fn select(&mut self, addr: u64) {
        self.selected = Some(addr);
        if let Some(off) = self.loaded.as_ref().and_then(|l| l.file_offset_of(addr)) {
            self.hex_offset = off;
        }
    }

}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}

impl App {
    /// Draws one frame. Kept separate from `eframe::App::ui` so tests can drive it without a window.
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.apply_settings(&ctx);
        self.apply_language(&ctx);
        self.poll();
        self.poll_pick(&ctx);
        self.poll_plugins();

        let dropped: Option<PathBuf> = ctx.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()));
        if let Some(p) = dropped {
            self.path_input = p.to_string_lossy().into_owned();
            self.open(&p, &ctx);
        }

        egui::Panel::top("top").show(ui, |ui| self.top_bar(ui, &ctx));
        egui::Panel::bottom("bottom").resizable(true).default_size(200.0).show(ui, |ui| self.bottom_panel(ui));
        egui::Panel::left("left").resizable(true).default_size(340.0).show(ui, |ui| self.left_panel(ui));
        egui::Panel::right("hex").resizable(true).default_size(560.0).show(ui, |ui| self.hex_panel(ui));
        egui::CentralPanel::default().show(ui, |ui| self.central_panel(ui));
        self.plugin_dialogs(&ctx);
    }

}

#[cfg(test)]
mod tests;
