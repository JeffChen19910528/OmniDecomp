# Security model

## Threat model
Every input file is hostile. Threats: malformed headers causing out-of-bounds reads, integer overflow in size/offset fields, decompression or output bombs, path traversal in output names, untrusted strings reaching a UI as markup.

## Controls
- Static analysis only; analyzed files are never executed or loaded into the process.
- All offset/length arithmetic checked; reads bounds-validated; no `unsafe` in parsers.
- Limits: max file size, max sections/symbols/strings, output size, wall-clock timeout, cancellation.
- Output paths normalized and validated; originals never modified.
- No network, no telemetry. Logs omit full paths and file contents.
- Third-party engines recorded in `THIRD_PARTY_NOTICES.md` with license and version.
- Robustness (Phase 5): `cargo test -p omnidecomp-app --test robustness` mutates every sample kind (PE32/64, ELF64/32-BE, Mach-O, .NET, PDB reference, pdata, eh_frame, Java class) with seeded byte flips and truncation and drives each result through the whole pipeline (symbols, debug info, .NET, strings, disassembly, functions, CFG, call graph, report); random-garbage inputs with planted magics; zero/cancelled/tiny limits. Parser-level mutation tests also exist per format. These are deterministic regression tests, not coverage-guided fuzzing: libFuzzer (cargo-fuzz) needs a nightly toolchain and a C++ toolchain, which the dev machine does not have, so no coverage-guided fuzzing has been run.
- Plugins (Phase 4, see PLUGIN_API.md): declarative manifests only, nothing loaded in-process. External decompilers start only when the plugin is enabled in the per-user state file (SHA-256 of manifest and program pinned) and the run passes `--allow-external-exec`; no shell, cleared environment, closed stdin, timeout/cancel kill, output cap, control characters stripped from output. There is no OS-level sandbox: an enabled decompiler runs with the user's rights. The GUI adds two confirmations that are never remembered: trusting an external plugin, and starting its program for one run (the window shows the program and arguments).

## Out of scope
License/DRM bypass, credential theft, malware concealment, unsandboxed dynamic analysis.
