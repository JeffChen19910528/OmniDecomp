# ADR 0001: Core language and stack

Status: proposed

## Options
| | A. Rust core + CLI (GUI later via Tauri) | B. .NET 10 core + CLI (Avalonia GUI) | C. Python core |
|---|---|---|---|
| Memory safety for hostile parsers | Strong | Strong (managed) | Strong, slow |
| x86 engine | `iced-x86` (MIT, pure Rust, no C toolchain) | Iced (C# port, MIT) | Capstone bindings (needs native lib) |
| .NET/IL decompile later | Via external ILSpy subprocess | Native ecosystem (ILSpy/ICSharpCode.Decompiler) | subprocess |
| Cross-platform CLI | Single static binary | Needs runtime or self-contained publish | Needs interpreter |
| GUI | Tauri/egui, more work | Avalonia, mature | Qt, heavy |
| Env readiness | rustc/cargo 1.99 present | SDK 10.0.402 present | 3.11 present |

Environment note: no gcc/cmake/MSVC found, so Capstone (C) is not buildable here; this favors a pure-Rust or managed engine.

## Recommendation: A (Rust)
Best fit for hostile-input parsing, single-binary CLI, and a pure-Rust disassembler with a permissive license. Trade-off: .NET and Java decompilation will go through optional external engines (ILSpy, CFR) as subprocess adapters, and the GUI is more effort than with Avalonia. Choose B if the GUI and .NET decompilation matter more than the CLI.

Licenses must be re-verified before adding each crate.
