//! Where plugins and their enabled-state live, resolved from explicit values, environment and defaults.
//! Shared by the CLI and the GUI so both read and write the same state.

use crate::registry::Registry;
use omnidecomp_core::{Error, ErrorCode};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Locations {
    pub dir: PathBuf,
    /// `None` when no per-user config directory exists; state can then be read (as empty) but not saved.
    pub state: Option<PathBuf>,
}

impl Locations {
    /// Order: explicit value, `OMNIDECOMP_PLUGINS_DIR` / `OMNIDECOMP_STATE_FILE`, then the default
    /// (`<exe dir>/plugins`, and the per-user config directory).
    pub fn resolve(dir: Option<PathBuf>, state: Option<PathBuf>) -> Self {
        let dir = dir
            .or_else(|| std::env::var_os("OMNIDECOMP_PLUGINS_DIR").map(PathBuf::from))
            .or_else(|| std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join("plugins"))))
            .unwrap_or_else(|| PathBuf::from("plugins"));
        let state = state.or_else(|| std::env::var_os("OMNIDECOMP_STATE_FILE").map(PathBuf::from)).or_else(|| {
            let base = if cfg!(windows) {
                std::env::var_os("APPDATA").map(PathBuf::from)
            } else {
                std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            };
            base.map(|b| b.join("OmniDecomp").join("plugins.json"))
        });
        Self { dir, state }
    }

    pub fn registry(&self) -> Result<Registry, Error> {
        Registry::load(&self.dir, self.state.as_deref().unwrap_or_else(|| Path::new("")))
    }

    /// For operations that change state: refuse rather than silently not saving.
    pub fn writable_registry(&self) -> Result<Registry, Error> {
        if self.state.is_none() {
            return Err(Error::new(ErrorCode::InvalidArgument, "cannot find a per-user config directory; pass --state-file"));
        }
        self.registry()
    }
}
