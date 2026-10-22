# ADR 0002: Desktop GUI toolkit

Status: accepted (2026-10-22)

## Context
The project specification's Phase 3 asks for a desktop UI (file view, disassembly, search, cross-references, theme and font settings) that is separated from the core and handles large inputs. The dev machine has no C toolchain, and the core is Rust (ADR 0001).

## Options
- **egui / eframe 0.36.2 (chosen)**: pure Rust, MIT OR Apache-2.0, builds here with no C compiler, immediate-mode with virtualized rows (`ScrollArea::show_rows`) that suits 1M-row disassembly lists.
- Tauri / web UI: needs a WebView runtime plus a JS toolchain; text from analyzed files would flow through an HTML renderer, which the project specification (section 8.5) asks us to avoid.
- Slint / iced: viable, but heavier styling work or less mature virtualized lists for this use.
- .NET WPF/Avalonia: would add a second language and runtime for no benefit.

## Decision
`crates/gui` (binary `omnidecomp-gui`) uses eframe with the `glow` backend. All logic that is not drawing lives in `crates/viewmodel` (no egui dependency) so it is unit-tested without a window. The GUI never reads files itself: it calls the application layer on a worker thread (progress and cancel through `Context::with_cancel`).

## Consequences
- Untrusted strings are drawn as plain egui labels, never interpreted as markup.
- Pinned `=0.36.2`; egui's API changes between minor versions, so upgrades are deliberate.
- The binary bundles egui's default fonts (OFL-1.1 / Ubuntu-font-1.0 notices are required for a release).
- The GUI is split into a library (`App::show`) and a thin `main.rs`, so `egui_kittest` (dev-dependency, accessibility-tree driven, no GPU) can click, type, drop files and read widget geometry in `cargo test`. Pixel-level rendering, the OS drag-and-drop path and the real native file dialog are still checked by hand.
- The file dialog uses `rfd` (MIT, no C toolchain with default features) on a short-lived worker thread, behind a `FilePicker` closure so tests can replace it.
- CFG and call-graph views are drawn with egui (nodes are buttons, edges are painted shapes). The layered layout is plain data in `viewmodel::graph`, capped at 400 nodes; the call graph shows the neighbourhood (depth 1-6) of the selected function, never the whole program.
