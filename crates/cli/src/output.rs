//! Small output helpers shared by the command handlers.

use serde::Serialize;

pub(crate) fn json_out<T: Serialize>(v: &T) {
    // Serializing our own plain data models cannot fail.
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

/// Prints `warning: ...` on stderr when a limit cut the result short.
pub(crate) fn warn_if(truncated: bool, message: &str) {
    if truncated {
        eprintln!("warning: {message}");
    }
}

pub(crate) fn notes(notes: &[impl std::fmt::Display]) {
    for n in notes {
        eprintln!("note: {n}");
    }
}
