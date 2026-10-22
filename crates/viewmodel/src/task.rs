//! Background loading: a worker thread with progress and cancel that the UI polls each frame.

use omnidecomp_core::{
    Error, ErrorCode, Limits,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use crate::loaded::{load_gated, Loaded};

/// A load running on a worker thread. The UI polls it each frame; dropping or cancelling it stops the work.
pub struct Task {
    rx: Receiver<Result<Loaded, Error>>,
    cancel: Arc<AtomicBool>,
    status: Arc<Mutex<String>>,
    done: bool,
}

pub fn start_load(path: PathBuf, limits: Limits, on_progress: impl Fn() + Send + 'static) -> Task {
    start_load_gated(path, limits, None, on_progress)
}

pub fn start_load_gated(
    path: PathBuf,
    limits: Limits,
    plugins: Option<omnidecomp_plugins::Locations>,
    on_progress: impl Fn() + Send + 'static,
) -> Task {
    let (tx, rx) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let status = Arc::new(Mutex::new("starting".to_string()));
    let (c, s) = (Arc::clone(&cancel), Arc::clone(&status));
    std::thread::spawn(move || {
        let report = |phase: &str| {
            if let Ok(mut g) = s.lock() {
                *g = phase.to_string();
            }
            on_progress();
        };
        let result = load_gated(&path, limits, &c, &report, plugins.as_ref());
        let _ = tx.send(result);
        on_progress();
    });
    Task { rx, cancel, status, done: false }
}

impl Task {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn status(&self) -> String {
        self.status.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// `Some` exactly once, when the worker has finished.
    pub fn poll(&mut self) -> Option<Result<Loaded, Error>> {
        if self.done {
            return None;
        }
        match self.rx.try_recv() {
            Ok(r) => {
                self.done = true;
                Some(r)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.done = true;
                Some(Err(Error::new(ErrorCode::Cancelled, "analysis worker stopped unexpectedly")))
            }
        }
    }
}
