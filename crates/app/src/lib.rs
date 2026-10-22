//! Application layer: loading, analysis workflows, reports and safe output. UI-independent.
//!
//! One module per workflow; this file only declares them and re-exports the public API so callers keep
//! writing `omnidecomp_app::analyze(..)`. Modules depend on `analysis` (the parsed input) and, for
//! graphs and reports, on `functions`; none of them depend on `decompile` or `engines`.

mod analysis;
mod decompile;
mod disasm;
mod engines;
mod export;
mod functions;
mod graphs;
mod output;
mod report;
mod strings;

pub use analysis::{analyze, debug_info, dotnet, java_class, read_input, symbols, Analysis};
pub use decompile::{decompile, detect_runtime, plan_decompile, DecompileResult};
pub use disasm::{disassemble, DisasmOptions};
pub use engines::engines;
pub use export::{export_report, ExportFormat};
pub use functions::{functions, functions_for, soft_ranges};
pub use graphs::{call_graph, call_graph_for, call_graph_to_dot, cfg, cfg_for, cfg_to_dot};
pub use output::write_output;
pub use report::build_report;
pub use strings::extract_strings;

#[cfg(test)]
mod tests;
