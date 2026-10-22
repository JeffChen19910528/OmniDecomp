//! Plugins tab and Decompile tab. Draws only: every decision (what may run, hash checks, the actual child
//! process) is made by `omnidecomp-viewmodel::jobs` and below. Two confirmations exist on purpose and are never
//! remembered: trusting an external plugin, and starting its program for one run.
//!
//! Text from plugin manifests and from the decompiler is untrusted and is shown as plain labels.

use super::{App, CenterTab};
use crate::i18n::{tr, trf, Lang};
use eframe::egui::{self, Color32, RichText};
use omnidecomp_viewmodel::jobs::{
    enabled_decompilers, file_label, plan_decompile, plugin_rows, set_plugin_enabled, split_lines, start_decompile, Job, Plan,
};
use omnidecomp_viewmodel::{DecompileResult, Locations, PluginRecord};
use std::path::PathBuf;

const RED: Color32 = Color32::from_rgb(220, 70, 70);
const AMBER: Color32 = Color32::from_rgb(220, 160, 60);

pub(crate) struct Output {
    pub(crate) header: String,
    pub(crate) notes: Vec<String>,
    pub(crate) lines: Vec<String>,
}

pub(crate) struct PluginUi {
    pub(crate) loc: Locations,
    /// `None` until first needed or after a change; `Err` is the message to show.
    pub(crate) rows: Option<Result<Vec<PluginRecord>, String>>,
    pub(crate) notice: Option<String>,
    pub(crate) confirm_enable: Option<PluginRecord>,
    pub(crate) engine: Option<String>,
    pub(crate) plan: Option<Job<Plan>>,
    pub(crate) confirm_run: Option<Plan>,
    pub(crate) run: Option<(Job<DecompileResult>, String)>,
    pub(crate) output: Option<Output>,
    pub(crate) error: Option<String>,
}

fn fmt_err(e: &omnidecomp_core::Error) -> String {
    format!("error[{}]: {}", e.code.as_str(), e.message)
}

impl PluginUi {
    pub fn new(loc: Locations) -> Self {
        Self { loc, rows: None, notice: None, confirm_enable: None, engine: None, plan: None, confirm_run: None, run: None, output: None, error: None }
    }

    fn refresh(&mut self) {
        self.rows = Some(plugin_rows(&self.loc).map_err(|e| fmt_err(&e)));
    }

    fn rows(&mut self) -> &Result<Vec<PluginRecord>, String> {
        if self.rows.is_none() {
            self.refresh();
        }
        self.rows.as_ref().expect("just filled")
    }

    fn toggle(&mut self, id: &str, enable: bool, log: &mut Vec<String>, lang: Lang) {
        match set_plugin_enabled(&self.loc, id, enable) {
            Ok(()) => {
                let msg = if enable { trf(lang, "plugin {} enabled", &[id]) } else { trf(lang, "plugin {} disabled", &[id]) };
                log.push(msg.clone());
                self.notice = Some(msg);
            }
            Err(e) => {
                let msg = fmt_err(&e);
                log.push(msg.clone());
                self.notice = Some(msg);
            }
        }
        self.refresh();
    }

    /// True while any worker is running (the Decompile button is disabled meanwhile).
    fn busy(&self) -> bool {
        self.plan.is_some() || self.run.is_some() || self.confirm_run.is_some()
    }
}

impl App {
    /// Collects finished plan/run jobs. Called every frame whatever tab is showing.
    pub(crate) fn poll_plugins(&mut self) {
        let lang = self.lang;
        let pl = &mut self.pl;
        if let Some(job) = pl.plan.as_mut() {
            if let Some(r) = job.poll() {
                pl.plan = None;
                match r {
                    Ok(plan) => pl.confirm_run = Some(plan),
                    Err(e) => {
                        let msg = fmt_err(&e);
                        self.log.push(msg.clone());
                        pl.error = Some(msg);
                    }
                }
            }
        }
        if let Some((job, label)) = pl.run.as_mut() {
            if let Some(r) = job.poll() {
                let label = std::mem::take(label);
                pl.run = None;
                match r {
                    Ok(d) => {
                        self.log.push(trf(lang, "decompiled {} with {} {}", &[&label, &d.engine, &d.engine_version]));
                        pl.output = Some(Output {
                            header: format!("{} {} ({}), {label}", d.engine_name, d.engine_version, d.runtime),
                            notes: d.notes.iter().map(|s| tr(lang, s).to_string()).collect(),
                            lines: split_lines(&d.text),
                        });
                        pl.error = None;
                    }
                    Err(e) => {
                        let msg = fmt_err(&e);
                        self.log.push(msg.clone());
                        pl.error = Some(msg);
                    }
                }
            }
        }
    }

    pub(crate) fn plugins_panel(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        ui.horizontal(|ui| {
            ui.label(RichText::new(tr(lang, "Plugins")).strong());
            if ui.button(tr(lang, "Refresh")).clicked() {
                self.pl.refresh();
                self.pl.notice = None;
            }
            ui.label(trf(lang, "plugins folder: {}", &[&self.pl.loc.dir.display().to_string()]));
        });
        ui.label(tr(lang, "Plugins are declarative manifests; nothing is loaded into this program. An external decompiler is started only after you enable it here and confirm a run on the Decompile tab."));
        if self.pl.loc.state.is_none() {
            ui.colored_label(AMBER, tr(lang, "No per-user config folder was found, so changes cannot be saved. Start with --state-file via the command line tool, or set OMNIDECOMP_STATE_FILE."));
        }
        if let Some(n) = &self.pl.notice {
            ui.label(n.clone());
        }
        ui.separator();
        let rows = match self.pl.rows() {
            Ok(r) => r.clone(),
            Err(e) => {
                ui.colored_label(RED, e.clone());
                return;
            }
        };
        let mut toggle: Option<(String, bool)> = None;
        let mut ask_enable: Option<PluginRecord> = None;
        egui::ScrollArea::vertical().id_salt("plugin-rows").show(ui, |ui| {
            for r in &rows {
                ui.horizontal_wrapped(|ui| {
                    let mut text = RichText::new(format!("{} {} [{}/{}] {}", r.id, r.version, r.origin, r.kind, r.status)).monospace();
                    if r.status == "invalid" || r.status == "incompatible" {
                        text = text.color(RED);
                    }
                    ui.label(text);
                    match r.status {
                        "enabled" => {
                            if ui.button(trf(lang, "Disable {}", &[&r.id])).clicked() {
                                toggle = Some((r.id.clone(), false));
                            }
                        }
                        "disabled" if ui.button(trf(lang, "Enable {}", &[&r.id])).clicked() => {
                            if r.origin == "external" {
                                ask_enable = Some(r.clone());
                            } else {
                                toggle = Some((r.id.clone(), true));
                            }
                        }
                        _ => {}
                    }
                });
                ui.label(format!("    {}  | {}: {}{}", r.name, tr(lang, "license"), r.license, r.source.as_ref().map_or(String::new(), |s| format!(" | {}: {s}", tr(lang, "source")))));
                if !r.handles.is_empty() {
                    ui.label(format!("    {}: {}", tr(lang, "handles"), r.handles.join(", ")));
                }
                if let Some(why) = &r.reason {
                    ui.colored_label(AMBER, format!("    {why}"));
                }
                ui.add_space(4.0);
            }
        });
        if let Some(r) = ask_enable {
            self.pl.confirm_enable = Some(r);
        }
        if let Some((id, on)) = toggle {
            self.pl.toggle(&id, on, &mut self.log, lang);
        }
    }

    pub(crate) fn plugin_dialogs(&mut self, ctx: &egui::Context) {
        let lang = self.lang;
        if let Some(r) = self.pl.confirm_enable.clone() {
            let mut decision: Option<bool> = None;
            egui::Window::new(tr(lang, "Trust this plugin?")).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                ui.label(RichText::new(format!("{} {}", r.name, r.version)).strong());
                ui.label(trf(lang, "license: {}   source: {}", &[&r.license, r.source.as_deref().unwrap_or(tr(lang, "(none)"))]));
                ui.label(tr(lang, "Enabling records a fingerprint (SHA-256) of the plugin manifest and of the program it runs. If either changes, the plugin stops working until you enable it again."));
                ui.label(tr(lang, "When you decompile, that program runs with your user rights. There is no sandbox. Enable it only if you trust it."));
                ui.horizontal(|ui| {
                    if ui.button(trf(lang, "Trust and enable {}", &[&r.id])).clicked() {
                        decision = Some(true);
                    }
                    if ui.button(tr(lang, "Cancel")).clicked() {
                        decision = Some(false);
                    }
                });
            });
            match decision {
                Some(true) => {
                    self.pl.confirm_enable = None;
                    self.pl.toggle(&r.id, true, &mut self.log, lang);
                }
                Some(false) => self.pl.confirm_enable = None,
                None => {}
            }
        }

        if let Some(plan) = self.pl.confirm_run.clone() {
            let mut decision: Option<bool> = None;
            egui::Window::new(tr(lang, "Start an external program?")).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                ui.label(RichText::new(format!("{} {} ({})", plan.engine_name, plan.engine_version, plan.runtime)).strong());
                ui.label(trf(lang, "program: {}", &[&plan.program]));
                let args: Vec<String> = plan.args.iter().map(|a| a.replace("{input}", &plan.input.to_string_lossy())).collect();
                ui.label(trf(lang, "arguments: {}", &[&args.join(" ")]));
                ui.label(tr(lang, "The file is only passed to it as a path. OmniDecomp does not execute the file, but this decompiler runs with your user rights and may read it fully. This permission is for this run only."));
                ui.horizontal(|ui| {
                    if ui.button(tr(lang, "Allow and run")).clicked() {
                        decision = Some(true);
                    }
                    if ui.button(tr(lang, "Cancel run")).clicked() {
                        decision = Some(false);
                    }
                });
            });
            match decision {
                Some(true) => {
                    self.pl.confirm_run = None;
                    let repaint = ctx.clone();
                    let label = file_label(&plan.input);
                    self.log.push(trf(lang, "starting {} on {}", &[&plan.engine, &label]));
                    self.pl.error = None;
                    self.pl.output = None;
                    self.pl.run = Some((start_decompile(&plan, self.pl.loc.clone(), move || repaint.request_repaint()), label));
                }
                Some(false) => {
                    self.pl.confirm_run = None;
                    self.log.push(tr(lang, "decompile cancelled before starting").to_string());
                }
                None => {}
            }
        }
    }

    pub(crate) fn decompile_panel(&mut self, ui: &mut egui::Ui) {
        let lang = self.lang;
        let ctx = ui.ctx().clone();
        let target = self.path_input.trim().to_string();
        ui.label(RichText::new(tr(lang, "Decompile with an external engine")).strong());
        ui.label(tr(lang, "Works on .NET assemblies and Java .class files (the path in the File box). Native code has no decompiler here."));
        let rows = match self.pl.rows() {
            Ok(r) => r.clone(),
            Err(e) => {
                ui.colored_label(RED, e.clone());
                return;
            }
        };
        let engines: Vec<PluginRecord> = enabled_decompilers(&rows).into_iter().cloned().collect();
        if self.pl.engine.as_ref().is_none_or(|e| !engines.iter().any(|r| &r.id == e)) {
            self.pl.engine = engines.first().map(|r| r.id.clone());
        }
        if engines.is_empty() {
            ui.colored_label(AMBER, tr(lang, "No decompiler is enabled. Open the Plugins tab and enable one (for .NET: install ilspycmd, then Enable ilspycmd)."));
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(tr(lang, "file:"));
            ui.label(RichText::new(if target.is_empty() { tr(lang, "(enter a path above)") } else { target.as_str() }).monospace());
        });
        ui.horizontal(|ui| {
            let selected = self.pl.engine.clone().and_then(|id| engines.iter().find(|r| r.id == id).map(|r| format!("{} {}", r.id, r.version)));
            egui::ComboBox::from_id_salt("decompile-engine").selected_text(selected.unwrap_or_else(|| tr(lang, "(none)").to_string())).show_ui(ui, |ui| {
                for r in &engines {
                    ui.selectable_value(&mut self.pl.engine, Some(r.id.clone()), format!("{} {}", r.id, r.version));
                }
            });
            let can = !target.is_empty() && self.pl.engine.is_some() && !self.pl.busy();
            if ui.add_enabled(can, egui::Button::new(tr(lang, "Decompile this file"))).clicked() {
                if let Some(engine) = self.pl.engine.clone() {
                    let repaint = ctx.clone();
                    self.pl.error = None;
                    self.pl.plan = Some(plan_decompile(PathBuf::from(&target), self.pl.loc.clone(), engine, move || repaint.request_repaint()));
                }
            }
            if self.pl.plan.is_some() {
                ui.spinner();
                ui.label(tr(lang, "checking plugin and file..."));
            }
            if let Some((job, label)) = &self.pl.run {
                if ui.button(tr(lang, "Cancel decompile")).clicked() {
                    job.cancel();
                }
                ui.spinner();
                ui.label(trf(lang, "decompiling {}...", &[label]));
            }
        });
        if let Some(e) = &self.pl.error {
            ui.colored_label(RED, e.clone());
        }
        if let Some(o) = &self.pl.output {
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(RichText::new(&o.header).strong());
                if ui.button(tr(lang, "Copy all")).clicked() {
                    ctx.copy_text(o.lines.join("\n"));
                }
                ui.label(trf(lang, "{} lines", &[&o.lines.len().to_string()]));
            });
            for n in &o.notes {
                ui.colored_label(AMBER, n.clone());
            }
            let font = egui::FontId::monospace(self.settings.font_size);
            let h = ui.text_style_height(&egui::TextStyle::Monospace);
            egui::ScrollArea::both().id_salt("decompiled").auto_shrink([false, false]).show_rows(ui, h, o.lines.len(), |ui, range| {
                for line in &o.lines[range] {
                    ui.label(RichText::new(line.as_str()).font(font.clone()));
                }
            });
        }
    }

    /// Entry used by `central_panel`.
    pub(crate) fn plugin_center(&mut self, ui: &mut egui::Ui) {
        match self.center {
            CenterTab::Plugins => self.plugins_panel(ui),
            _ => self.decompile_panel(ui),
        }
    }
}
