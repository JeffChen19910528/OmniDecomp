# Third-party notices

Direct dependencies (licenses read from `cargo metadata` on 2026-10-22). Transitive crates are all under MIT, Apache-2.0 or dual licenses with one of them; no copyleft-only crate was found. Re-check on every dependency change. `scripts/sbom.py` generates a CycloneDX 1.5 SBOM and a per-crate license table for the shipped binaries (normal dependencies of the CLI and GUI) and fails if any component lacks a declared license; both are included in the release package.

| Crate | Version | License | Used for |
|---|---|---|---|
| iced-x86 | 1.21.0 (pinned) | MIT | x86/x86-64 disassembly engine |
| yaxpeax-arm | 0.4.0 (pinned; released 2025-10-20) | 0BSD | AArch64 disassembly engine (pure Rust; 32-bit ARM decoder present but not used) |
| yaxpeax-arch | 0.3.3 (pinned) | 0BSD | reader/decoder traits used by yaxpeax-arm |
| eframe / egui | 0.36.2 (pinned) | MIT OR Apache-2.0 | desktop GUI (`omnidecomp-gui` only; glow/OpenGL backend, `default_fonts`) |
| rfd | 0.17.2 (pinned) | MIT | native file-open dialog in `omnidecomp-gui` (default features: Win32 on Windows, XDG portal/Wayland on Linux, AppKit on macOS; no GTK/C toolchain). Transitive: pollster (Apache-2.0/MIT), wayland-* (MIT), objc2-* (MIT / Zlib OR Apache-2.0 OR MIT), windows-sys (MIT OR Apache-2.0) |
| egui_kittest | 0.36.2 (pinned) | MIT OR Apache-2.0 | GUI interaction tests only (dev-dependency of `omnidecomp-gui`; no snapshot/wgpu features) |
| serde | 1.0.229 | MIT OR Apache-2.0 | serialization |
| serde_json | 1.0.154 | MIT OR Apache-2.0 | JSON output |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | SHA-256 |
| clap | 4.6.7 | MIT OR Apache-2.0 | CLI parsing |
| ctrlc | 3.5.2 | MIT/Apache-2.0 | Ctrl-C cancellation |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | tests only |

Transitive: bitvec 1.x and its helpers (MIT) via yaxpeax-arm. License read from crates.io metadata; re-run `cargo metadata` to confirm before release.

GUI transitive licenses (from `cargo metadata`, 311 packages in the workspace graph on 2026-10-22, after adding rfd): almost all MIT / Apache-2.0 / Zlib / BSD / 0BSD / ISC / Unlicense dual or single licenses. Items to keep in mind when distributing the GUI binary:
- `epaint_default_fonts` bundles fonts under OFL-1.1 and Ubuntu-font-1.0 (egui's `default_fonts` feature). Their notices must accompany a binary release; disabling `default_fonts` would remove them.
- `self_cell` is `Apache-2.0 OR GPL-2.0-only` and `r-efi` is `MIT OR Apache-2.0 OR LGPL-2.1-or-later`: both are dual licenses, used here under the permissive option.
- `clipboard-win` and `error-code` are BSL-1.0 (permissive).
- No crate in the graph is copyleft-only. The nine workspace crates themselves have no license field yet.

Plugin engines (Phase 4): `plugins/ilspycmd` (ILSpy command line, MIT) and `plugins/cfr` (CFR, MIT) ship as manifests plus NOTICE.md only. The engines are not bundled or redistributed; the user installs them. The plugin layer adds no third-party dependency (serde, serde_json and sha2 were already used).

Candidate engines not integrated: Capstone, Ghidra, ILSpy, CFR (license and version to be verified before adoption).
