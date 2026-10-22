//! Everything a command needs besides its own arguments: the job context (limits, deadline, Ctrl-C
//! cancellation) and where plugins live. Built once in `main`; commands only borrow it.

use crate::args::Cli;
use omnidecomp_app as app;
use omnidecomp_core::{Context, Error, Limits};
use omnidecomp_plugins::{Locations, Registry};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub(crate) struct Session {
    plugins: Locations,
    pub(crate) ctx: Context,
}

impl Session {
    pub(crate) fn new(cli: &Cli) -> Self {
        let limits = Limits {
            max_file_size: cli.max_file_size_mb.saturating_mul(1024 * 1024),
            timeout: Duration::from_secs(cli.timeout_secs),
            ..Limits::default()
        };
        let ctx = Context::new(limits);
        let cancel = ctx.cancel_handle();
        let _ = ctrlc::set_handler(move || cancel.store(true, Ordering::Relaxed));
        Self { plugins: Locations::resolve(cli.plugins_dir.clone(), cli.state_file.clone()), ctx }
    }

    pub(crate) fn registry(&self) -> Result<Registry, Error> {
        self.plugins.registry()
    }

    /// For commands that change state: refuses rather than silently not saving.
    pub(crate) fn writable_registry(&self) -> Result<Registry, Error> {
        self.plugins.writable_registry()
    }

    /// Parses `file` after checking that the plugins for its format and architecture are enabled.
    pub(crate) fn analyze(&self, file: &Path) -> Result<app::Analysis, Error> {
        let a = app::analyze(file, &self.ctx)?;
        self.registry()?.check_analysis(a.info.format, a.info.arch)?;
        Ok(a)
    }
}
