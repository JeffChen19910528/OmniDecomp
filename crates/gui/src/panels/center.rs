//! Central area: tab strip and dispatch to the disassembly, graph, decompile and plugin panels.

use crate::i18n::tr;
use crate::{App, CenterTab};
use eframe::egui::{self};

impl App {
    pub(crate) fn central_panel(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        ui.horizontal(|ui| {
            for (tab, name) in [(CenterTab::Disasm, tr(lang, "Disassembly")), (CenterTab::Cfg, tr(lang, "CFG")), (CenterTab::Calls, tr(lang, "Call graph")), (CenterTab::Decompile, tr(lang, "Decompile")), (CenterTab::Plugins, tr(lang, "Plugins"))] {
                ui.selectable_value(&mut self.center, tab, name);
            }
        });
        match self.center {
            CenterTab::Disasm => self.disasm_panel(ui),
            CenterTab::Cfg | CenterTab::Calls => self.graph_panel(ui),
            CenterTab::Decompile | CenterTab::Plugins => self.plugin_center(ui),
        }
    }
}
