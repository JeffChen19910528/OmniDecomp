//! CFG and call-graph pictures.

use crate::i18n::{tr, trf};
use crate::widgets::draw_graph;
use crate::{App, CenterTab, GraphState};
use eframe::egui::{self, Color32, RichText};
use omnidecomp_core::Limits;
use omnidecomp_viewmodel::graph::{call_layout, cfg_layout, MAX_GRAPH_NODES};
use omnidecomp_viewmodel::Theme;

impl App {
    /// Function the graph is about: the one containing the selection, else the lowest recovered one.
    pub(crate) fn graph_focus(&self) -> Option<u64> {
        let l = self.loaded.as_ref()?;
        self.selected.and_then(|a| l.function_containing(a)).or_else(|| l.functions.as_ref()?.functions.first().map(|f| f.address))
    }

    pub(crate) fn rebuild_graph(&mut self, focus: u64) {
        let lang = self.lang;
        let Some(l) = self.loaded.as_ref() else { return };
        let depth = if self.center == CenterTab::Calls { self.call_depth } else { 0 };
        let key = (self.center, focus, depth);
        if self.graph.as_ref().is_some_and(|g| g.key == key) {
            return;
        }
        let layout = if self.center == CenterTab::Cfg {
            l.cfg(focus, Limits::default()).map(|r| cfg_layout(&r)).map_err(|e| format!("error[{}]: {}", e.code.as_str(), e.message))
        } else {
            l.call_graph().map(|g| call_layout(g, focus, depth, MAX_GRAPH_NODES)).ok_or_else(|| tr(lang, "call graph unavailable for this file").to_string())
        };
        self.graph = Some(GraphState { key, layout });
    }

    pub(crate) fn graph_panel(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        let Some(focus) = self.graph_focus() else {
            ui.label(if self.loaded.is_some() { tr(lang, "No functions were recovered for this file, so there is no graph. See the Log tab.") } else { tr(lang, "Graphs appear here once a file is loaded.") });
            return;
        };
        if self.center == CenterTab::Calls {
            ui.horizontal(|ui| {
                ui.label(tr(lang, "depth"));
                ui.add(egui::Slider::new(&mut self.call_depth, 1..=6));
            });
        }
        self.rebuild_graph(focus);
        let name = self.loaded.as_ref().and_then(|l| l.name_at(focus));
        let Some(state) = self.graph.as_ref() else { return };
        let layout = match &state.layout {
            Ok(l) => l,
            Err(e) => {
                ui.colored_label(Color32::from_rgb(220, 70, 70), e);
                return;
            }
        };
        let who = format!("{}{focus:#x}", name.map_or(String::new(), |n| format!("{n} ")));
        let (nodes, edges) = (layout.nodes.len().to_string(), layout.edges.len().to_string());
        let cut = if layout.truncated { tr(lang, " (cut by a limit)") } else { "" };
        let summary = if self.center == CenterTab::Cfg {
            trf(lang, "CFG: blocks of {} - {} nodes, {} edges{}", &[&who, &nodes, &edges, cut])
        } else {
            trf(lang, "Calls: functions around {} - {} nodes, {} edges{}", &[&who, &nodes, &edges, cut])
        };
        ui.label(RichText::new(summary).weak());
        ui.label(RichText::new(tr(lang, "Derived from linear-sweep disassembly. Indirect jumps and calls are not resolved. Click a node to select it; double-click to show it in the disassembly.")).weak().small());
        let action = draw_graph(ui, layout, self.selected, self.settings.font_size, self.settings.theme == Theme::Dark, lang);
        if let Some((addr, open)) = action {
            self.select(addr);
            if open {
                self.center = CenterTab::Disasm;
                self.goto(addr);
            }
        }
    }
}
