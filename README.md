# OmniDecomp

[English](README.md) | [繁體中文](README.zh-TW.md)

A static analysis toolkit for executables, written in Rust. It reads PE, ELF and Mach-O files, disassembles x86 / x86-64 / AArch64 code, recovers functions, cross-references, control-flow and call graphs, and reads .NET and Java class metadata. A command-line tool and a desktop UI share one analysis core. Decompilation to C# or Java is done by external engines (ilspycmd, CFR) that you install and enable yourself.

**Static only.** Files you analyze are read, never executed, loaded or uploaded. There is no network access and no telemetry.

Status: all five planned phases (core, engines and reports, desktop UI, plugins and decompilation, hardening and release) are implemented. The version is 0.1.0 and no license has been chosen yet. What is and is not verified is listed in [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) and [docs/SUPPORTED_FORMATS.md](docs/SUPPORTED_FORMATS.md); please read them before relying on a feature.

## What it can do

| Area | Details |
|---|---|
| Formats | PE32 / PE32+, ELF32 / ELF64, thin Mach-O (fat/universal binaries are refused), .NET assemblies (metadata), Java `.class` (structure) |
| Disassembly | x86 / x86-64 with iced-x86, AArch64 with yaxpeax-arm. Linear sweep, Intel syntax |
| Analysis | symbols (imports, exports, ELF symtab), functions (entry point, symbols, `.pdata`, `.eh_frame`, direct calls), cross-references, CFG, call graph, strings, PE debug info (PDB reference) |
| Reports | JSON, text, CSV, HTML (CSV cells and HTML are escaped) |
| Decompilation | .NET (ilspycmd) and Java (CFR) through enabled plugins only; output is untrusted text |
| Desktop UI | file info, function / symbol / string lists, disassembly, hex view, search, cross-references, CFG and call-graph pictures, plugin management and decompile panel, dark / light themes, font settings, **English and Traditional Chinese** |

Unsupported formats or architectures fail with a specific error code; nothing is guessed.

## Install

Prebuilt zip packages are produced by `scripts/package.py`:

| Platform | Status |
|---|---|
| Windows 11 x86-64 | built, tested and smoke-tested |
| Linux x86-64 (glibc 2.39+, e.g. Ubuntu 24.04) | built, tested and smoke-tested under WSL2 |
| macOS (Apple silicon, Intel) | **not verified yet**: both targets pass a compile check, but it has not been run or tested on a Mac |

Unzip, then run `omnidecomp --version`. Details, verification of the SHA-256, upgrade, uninstall and troubleshooting: [docs/INSTALL.md](docs/INSTALL.md).

Build from source (Rust 1.99.0 is pinned by `rust-toolchain.toml`; all dependencies are pure Rust, no C toolchain needed):

```
cargo build --release
cargo test
cargo clippy --all-targets
```

## Command line

```
omnidecomp info <file> [--format json]
omnidecomp disasm <file> [--arch x86_64] [--section .text] [--max-instructions N] [--format json]
omnidecomp symbols <file>          omnidecomp functions <file>
omnidecomp xrefs <file> [--to 0x401000] [--from 0x401000]
omnidecomp cfg <file> --function 0x401000 [--format text|json|dot]
omnidecomp callgraph <file> [--format text|json|dot]
omnidecomp strings <file> [--min-length 4]
omnidecomp report <file> [--format json|text|csv|html] [--output report.json]
omnidecomp dotnet <assembly.dll>   omnidecomp java <file.class>
omnidecomp engines list
omnidecomp plugins list | enable <id> | disable <id>
omnidecomp decompile <assembly.dll|file.class> --engine ilspycmd --allow-external-exec [--output out.cs]
```

Global flags: `--max-file-size-mb` (default 256), `--timeout-secs` (default 60), `--plugins-dir`, `--state-file`. Errors print as `error[<code>]: message` on stderr.

Exit codes: 0 ok, 2 invalid argument, 3 I/O, 10 truncated, 11 malformed, 12 unsupported format, 13 unsupported architecture, 14 limit exceeded, 15 unknown engine, 16 invalid output path, 17 cancelled, 18 timeout, 19 unknown plugin, 20 plugin disabled, 21 plugin incompatible, 22 external engine failed.

The command-line messages are in English.

## Desktop UI

```
omnidecomp-gui [file]
```

Open a file with **Open file...**, by typing a path, or by dropping it on the window. Double-click a call target or a graph node, or click a cross-reference, to jump to it.

**Language.** Open the **View** menu and choose **English** or **繁體中文**. The choice is saved in `gui.json` next to the plugin state file, and on a first start the system locale (`LANG`, `LC_ALL`) is used. Traditional Chinese needs a font that can draw Chinese characters: egui's built-in fonts cannot, and no font is bundled. The program uses one that is already installed (Microsoft JhengHei on Windows, Noto Sans CJK on Linux, PingFang on macOS; only the Windows font has been tried) and only loads it when Chinese is selected; if none is found, Chinese is unavailable and the menu says why. Set `OMNIDECOMP_CJK_FONT=<path>[,<face index>]` to name a font yourself. Only the interface is translated; file contents, error codes, engine and decompiler output stay as they are.

## Plugins and decompilation

A plugin is a directory with a `plugin.json`; nothing is loaded into the program. External decompilers start only when all of these hold: the plugin is enabled (the SHA-256 of its manifest and program is recorded), the checks pass again at run time, and you consent to that run (`--allow-external-exec`, or *Allow and run* in the UI). The engine runs with your user rights; there is no sandbox. See [docs/PLUGIN_API.md](docs/PLUGIN_API.md). The engines are not bundled:

```
dotnet tool install -g ilspycmd
omnidecomp plugins enable ilspycmd
omnidecomp decompile app.dll --engine ilspycmd --allow-external-exec
```

CFR needs a small `cfr` launcher around its jar (see `plugins/cfr/NOTICE.md`).

## Security

Every input is treated as hostile: bounds-checked reads, checked arithmetic, size / count / time limits, cancellation, validated output paths, control characters stripped from displayed names, no `unsafe` anywhere. Mutation tests (byte flips, truncation) drive every sample through the whole pipeline; they are regression tests, not coverage-guided fuzzing. Details: [docs/SECURITY.md](docs/SECURITY.md).

## Project layout

```
crates/core       data model, error codes, limits, cancellation
crates/formats    PE / ELF / Mach-O / .NET / Java parsers
crates/engines    disassembly engines (iced-x86, yaxpeax-arm)
crates/app        workflows shared by the CLI and the UI
crates/plugins    plugin manifests, enable state, the only place a third-party program is started
crates/cli        command-line front end
crates/viewmodel  UI state without any UI toolkit
crates/gui        desktop front end (egui)
crates/testsamples  self-built sample files and a stand-in decompiler for tests
```

More: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/ROADMAP.md](docs/ROADMAP.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

Not chosen yet. Third-party licenses of everything compiled in are listed in `THIRD_PARTY_NOTICES.md` and, for a release, in `THIRD_PARTY_LICENSES.md` and the SBOM (`omnidecomp.cdx.json`).
