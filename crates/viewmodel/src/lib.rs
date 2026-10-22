//! UI-independent view model for the desktop front end. Everything here is plain data and logic so it
//! can be tested without a window. One module per concern:
//!
//! - `loaded`: the loaded model of one file and its lookups (`search` adds searching)
//! - `task`: background loading with progress and cancel
//! - `jobs`: plugin management and decompilation as background jobs
//! - `graph`: layered layout for the CFG and call-graph pictures
//! - `settings`, `mnemonic`: display preferences and instruction classes
//!
//! Text coming from analyzed files is untrusted. This crate only produces `String`s; a front end must
//! show them as plain text, never as markup.

pub mod graph;
pub mod jobs;
mod loaded;
mod mnemonic;
mod search;
mod settings;
mod task;

pub use loaded::{load, load_gated, Loaded};
pub use mnemonic::{mnemonic_class, MnemonicClass};
pub use omnidecomp_app::DecompileResult;
pub use omnidecomp_plugins::{Locations, PluginRecord};
pub use search::{parse_address, Hit, HitKind, Scope};
pub use settings::{AddressFormat, Settings, Theme, MAX_FONT, MAX_SPACING, MIN_FONT};
pub use task::{start_load, start_load_gated, Task};

#[cfg(test)]
mod tests;
