//! Validated writing of result files.

use omnidecomp_core::{
    Error, ErrorCode, Result,
};
use std::fs::{self};
use std::path::{Component, Path};
use crate::analysis::io_err;

/// Writes `content` after validating the destination: no `..` components, parent must exist,
/// not a directory, and never the input file itself.
pub fn write_output(path: &Path, content: &[u8], input: &Path) -> Result<()> {
    let bad = |m: &str| Error::new(ErrorCode::InvalidOutputPath, m.to_string());
    if path.as_os_str().is_empty() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(bad("output path must not be empty or contain '..'"));
    }
    if path.is_dir() {
        return Err(bad("output path is a directory"));
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if !parent.is_dir() {
        return Err(bad("output directory does not exist"));
    }
    if let (Ok(o), Ok(i)) = (fs::canonicalize(path), fs::canonicalize(input)) {
        if o == i {
            return Err(bad("refusing to overwrite the input file"));
        }
    }
    fs::write(path, content).map_err(|e| io_err("cannot write output", e))
}
