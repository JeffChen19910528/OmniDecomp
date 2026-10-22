//! Choosing a file (native dialog on its own thread) and loading it in the background.

use crate::i18n::trf;
use crate::App;
use eframe::egui::{self};
use omnidecomp_core::Limits;
use omnidecomp_viewmodel::start_load_gated;
use std::path::PathBuf;
use std::sync::mpsc::{channel, TryRecvError};
use std::sync::Arc;

/// Chooses a file to open. The default shows the native dialog; tests install a fake.
pub type FilePicker = Arc<dyn Fn() -> Option<PathBuf> + Send + Sync>;

pub(crate) fn native_picker() -> FilePicker {
    Arc::new(|| rfd::FileDialog::new().set_title("Open file / 開啟檔案").pick_file())
}

impl App {
    /// Replaces the file chooser (used by tests; the real one opens a native dialog).
    pub fn set_file_picker(&mut self, picker: FilePicker) {
        self.picker = picker;
    }

    /// Runs the chooser on its own thread so a slow or modal dialog never freezes the window.
    pub(crate) fn pick_file(&mut self, ctx: &egui::Context) {
        if self.pending_pick.is_some() {
            return;
        }
        let (tx, rx) = channel();
        let (picker, repaint) = (Arc::clone(&self.picker), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(picker());
            repaint.request_repaint();
        });
        self.pending_pick = Some(rx);
    }

    pub(crate) fn poll_pick(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.pending_pick else { return };
        match rx.try_recv() {
            Ok(choice) => {
                self.pending_pick = None;
                if let Some(p) = choice {
                    self.path_input = p.to_string_lossy().into_owned();
                    self.open(&p, ctx);
                }
            }
            Err(TryRecvError::Empty) => ctx.request_repaint_after(std::time::Duration::from_millis(100)),
            Err(TryRecvError::Disconnected) => self.pending_pick = None,
        }
    }

    pub(crate) fn open(&mut self, path: &std::path::Path, ctx: &egui::Context) {
        if let Some(t) = &self.task {
            t.cancel();
        }
        self.error = None;
        let lang = self.lang;
        let name = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        self.log.push(trf(lang, "opening {}", &[&name]));
        let repaint = ctx.clone();
        self.task = Some(start_load_gated(path.to_path_buf(), Limits::default(), Some(self.pl.loc.clone()), move || repaint.request_repaint()));
    }

    pub(crate) fn poll(&mut self) {
        let lang = self.lang;
        let Some(task) = self.task.as_mut() else { return };
        if let Some(result) = task.poll() {
            self.task = None;
            match result {
                Ok(l) => {
                    self.log.push(trf(lang, "loaded {} ({} instructions)", &[&l.name, &l.instructions().len().to_string()]));
                    self.log.extend(l.notes.iter().cloned());
                    self.selected = None;
                    self.graph = None;
                    self.results.clear();
                    self.hex_offset = 0;
                    self.jump_row = if l.instructions().is_empty() { None } else { Some(0) };
                    self.loaded = Some(l);
                }
                Err(e) => {
                    let msg = format!("error[{}]: {}", e.code.as_str(), e.message);
                    self.log.push(msg.clone());
                    self.error = Some(msg);
                }
            }
        }
    }
}
