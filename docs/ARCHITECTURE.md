# Architecture

## Layers
Front ends (CLI, desktop UI) -> view model / application workflows -> parsers, engines and plugins -> core (data model, errors, limits). Security (limits, cancellation, sanitizing, consent) cuts across all of them.

Core depends on neither a UI nor a specific engine. Engines are reached only through adapter traits. The only code that starts a third-party program is `crates/plugins/src/run.rs`.

## Crates and allowed dependencies
Non-dev dependencies only. `crates/core/tests/architecture.rs` enforces this table, a 700-line limit for production source files, and the "only plugins start processes" rule, so a violation fails `cargo test`.

| Crate | Role | May depend on |
|---|---|---|
| `core` | data model, `ErrorCode` with stable exit codes, `Limits`, `Context` (limits + cancel + deadline) | nothing |
| `formats` | PE, ELF, Mach-O, .NET metadata and Java class parsers; all reads are bounds-checked | core |
| `engines` | `DisassemblyEngine` trait, iced-x86 and yaxpeax-arm adapters | core |
| `plugins` | plugin manifests, enable state, compatibility checks, the process runner | core |
| `app` | analysis workflows shared by every front end | core, formats, engines, plugins |
| `viewmodel` | UI state without any UI toolkit | core, app, plugins |
| `cli` | command-line front end | core, app, plugins |
| `gui` | desktop front end (egui) | core, viewmodel |
| `testsamples` | self-built sample files and a stand-in decompiler (dev-dependency only) | nothing |

## Inside each crate
Each crate's `lib.rs` (or `main.rs`) only declares modules and re-exports the public API; behaviour lives in one module per responsibility. A module imports what it uses explicitly, so its `use` lines are its dependency list.

`app`: `analysis` (read + parse, the `Analysis` value everything starts from) -> `disasm`, `strings` -> `functions` -> `graphs`, `report` (-> `export`); `engines` (detection of optional decompilers) and `decompile` stand apart; `output` validates result paths.

`viewmodel`: `loaded` (the model of one file) with `search`; `task` (background load); `jobs` (plugin management and decompile jobs); `graph` (layout); `settings`, `mnemonic`.

`cli`: `args` (grammar) -> `session` (limits, Ctrl-C, plugin locations) -> `commands::{binary, graphs, managed, report, plugins}` -> `output` helpers. `main.rs` only wires them and maps errors to exit codes.

`gui`: `App` (state and the frame loop) in `lib.rs`; `loading` (file dialog, background load), `appearance` (language, fonts, theme), `panels::*` (one file per screen area), `widgets` (drawing helpers), `plugin_ui` (plugins and decompile tabs, consent windows), `i18n` and `cjk` (interface language). Panels hold no state of their own.

## Data rules
Unknown data is `null`/`unknown` with a confidence level. Disassembly and decompiler output are separate kinds and are labelled with engine and version. Text from files and from external programs is untrusted: it is sanitized and shown as plain text.

## Decisions
`adr/0001-tech-stack.md` (Rust), `adr/0002-gui-toolkit.md` (egui).
