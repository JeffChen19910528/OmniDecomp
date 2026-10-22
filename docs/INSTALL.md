# Install, upgrade, uninstall, troubleshooting

OmniDecomp is a portable program: unzip it and run it. There is no installer, no service and no registry
entry. Everything it writes is listed under "What is stored where" below.

## Platforms

| Platform | Package | Status |
|---|---|---|
| Windows 11 x86-64 | `OmniDecomp-<version>-x86_64-pc-windows-msvc.zip` | built, tested and smoke-tested by hand |
| Linux x86-64 (glibc 2.39 or newer, e.g. Ubuntu 24.04) | `OmniDecomp-<version>-x86_64-unknown-linux-gnu.zip` | built, tested and smoke-tested by hand in Ubuntu 24.04 (WSL2); the GUI window opened under WSLg |
| macOS, Apple silicon and Intel | `...-aarch64-apple-darwin.zip`, `...-x86_64-apple-darwin.zip` | **not verified yet.** Both targets pass a compile check (`cargo check`), but it has not been built into a package, run or tested on a Mac, and no macOS package is provided. CI tries it on macOS runners as an experiment. |

Older Linux distributions (glibc below 2.39) cannot run the prebuilt Linux binaries; build from source there
(`cargo build --release`, Rust 1.99.0, no other tools needed).

## What you get

`OmniDecomp-<version>-<target>.zip` contains:

| Path | Purpose |
|---|---|
| `omnidecomp(.exe)` | command-line tool |
| `omnidecomp-gui(.exe)` | desktop UI |
| `plugins/` | plugin manifests (`ilspycmd`, `cfr`); the engines themselves are **not** included |
| `docs/` | this file, plugin API, security model, supported formats, acceptance list |
| `THIRD_PARTY_NOTICES.md`, `THIRD_PARTY_LICENSES.md` | licenses of everything compiled in |
| `omnidecomp.cdx.json` | CycloneDX 1.5 SBOM of the shipped binaries |
| `VERSION.json` | version, target, compiler and the SHA-256 of every file in the package |

## Verify the download

The release step writes `SHA256SUMS` next to the zip.

```
# Windows PowerShell
(Get-FileHash OmniDecomp-<version>-<target>.zip -Algorithm SHA256).Hash
# Linux / macOS
sha256sum -c SHA256SUMS
```

Compare with `SHA256SUMS`. A matching hash proves the file is the one that was built; it is not a code
signature (the binaries are not signed, so Windows SmartScreen may warn on first start).

After unzipping, `VERSION.json` lists the hash of each file if you want to check them individually.

## Install

1. Unzip anywhere you can write to, for example `C:\Tools\OmniDecomp`. Keep the `plugins` folder next to the
   executables: the default plugin directory is `<folder of the executable>/plugins`.
2. Run `omnidecomp --version`, then `omnidecomp plugins list`. The seven built-in capabilities
   (`format-pe`, `format-elf`, `format-macho`, `arch-x86`, `arch-arm64`, `runtime-dotnet`, `runtime-java`)
   are listed as enabled; `ilspycmd` and `cfr` are listed as disabled.
3. Linux: `unzip` keeps the executable bits. macOS (once packages exist): the first start of an unsigned download is
   blocked by Gatekeeper; after verifying the SHA-256, clear the quarantine flag with
   `xattr -dr com.apple.quarantine OmniDecomp-<version>-<target>` or allow it in System Settings, Privacy & Security.
4. Try it on a file: `omnidecomp info some.exe`. The GUI: `omnidecomp-gui` (or drop a file on it). Plugins can be enabled and used for decompiling from its Plugins and Decompile tabs; it shares the plugin settings with the command line.

The program only reads the files you give it. It never runs them, never uses the network and sends nothing.

### Optional: external decompilers

Decompiling to C# or Java needs a third-party engine that you install yourself. See `docs/PLUGIN_API.md`.
For .NET, for example:

```
dotnet tool install -g ilspycmd
omnidecomp plugins enable ilspycmd
omnidecomp decompile app.dll --engine ilspycmd --allow-external-exec
```

Enabling records a hash of the manifest and of the engine program; `--allow-external-exec` is required on
every run. The engine then runs with your user rights (there is no sandbox), so enable only engines you trust.

## Upgrade

1. Close the GUI.
2. Unzip the new version into a **new** folder (or replace the old folder's contents).
3. Run `omnidecomp plugins list` from the new folder.

Your settings survive an upgrade because they live outside the program folder (see below). Two things to
expect:

- A plugin whose manifest changed in the new version, or an engine you updated (for example a new
  `ilspycmd`), no longer matches the hash recorded when you enabled it. Runs fail with exit code 21
  (`plugin_incompatible`) until you review it and run `omnidecomp plugins enable <id>` again. This is by
  design.
- A plugin that needs a newer host than yours is listed as incompatible with the required version.

To roll back, unzip the previous version into its own folder. (Rolling back across a plugin API change has not been tested.)

## Uninstall

1. Delete the program folder.
2. Optionally delete the per-user state file (it only records which plugins you enabled and their hashes):
   - Windows: `%APPDATA%\OmniDecomp\plugins.json`
   - Linux and macOS: `$XDG_CONFIG_HOME/OmniDecomp/plugins.json`, or `~/.config/OmniDecomp/plugins.json` (macOS does not use `~/Library/Application Support`)
3. External engines are separate programs and are not removed by this. For ilspycmd:
   `dotnet tool uninstall -g ilspycmd`.

The GUI keeps its display settings (theme, font size) in memory only. The only file it writes is `gui.json` (the chosen language) in the same folder as the plugin state file; delete it too if you want a clean removal.

## What is stored where

| Item | Location |
|---|---|
| Program, plugin manifests | the folder you unzipped to (override plugins with `--plugins-dir` or `OMNIDECOMP_PLUGINS_DIR`) |
| Which plugins are enabled | the state file above (override with `--state-file` or `OMNIDECOMP_STATE_FILE`) |
| GUI language | `gui.json` beside the state file (`{"language":"en"}` or `"zh-TW"`) |
| Reports and decompiler output | only where you pass `--output`; existing inputs are never overwritten |

## Troubleshooting

Errors print as `error[<code>]: message` on stderr and set the exit code.

| Exit | Code | Meaning and what to do |
|---|---|---|
| 2 | `invalid_argument` | A flag is wrong or consent is missing. For `decompile`, add `--allow-external-exec`. |
| 3 | `io` | File missing, unreadable, or not a regular file. Check the path and permissions. |
| 10 | `truncated` | The file ends early (partial download, damaged). Re-download it. |
| 11 | `malformed` | The structure is invalid. Also: the plugin state file is corrupt; delete it as the message says. |
| 12 | `unsupported_format` | Not a PE, ELF, thin Mach-O, .NET assembly or Java `.class` (JAR/ZIP and universal Mach-O are refused). |
| 13 | `unsupported_arch` | Supported: x86, x86-64, AArch64. 32-bit ARM and others are refused rather than guessed. |
| 14 | `limit_exceeded` | A size or count limit was hit. Raise `--max-file-size-mb` or, for decompile, `--max-output-mb`. |
| 15 | `unknown_engine` | Engine id not known; see `omnidecomp engines list` and `omnidecomp plugins list`. |
| 16 | `invalid_output_path` | `--output` contains `..`, or points at the input. Choose another path. |
| 17 | `cancelled` | Ctrl-C or the GUI Cancel button. |
| 18 | `timeout` | Raise `--timeout-secs` (default 60). Large decompilations may need more. |
| 19 | `unknown_plugin` | No plugin with that id; check spelling with `plugins list`. |
| 20 | `plugin_disabled` | The plugin (or a built-in it depends on) is disabled: `plugins enable <id>`. |
| 21 | `plugin_incompatible` | Manifest or engine changed since you enabled it, or API/host version mismatch. Review, then enable again. |
| 22 | `external_engine_failed` | The engine would not start or exited with an error. The message includes its first error lines. Run the engine by hand on the same file to see the full output. |

Common situations:

- **"cannot start engine"**: the engine is not on `PATH` for the OmniDecomp process. The environment given to engines
  is limited to `PATH`, `SystemRoot`, `TEMP`/`TMP`/`TMPDIR`, `HOME`/`USERPROFILE`, `JAVA_HOME` and `DOTNET_ROOT`.
  Start OmniDecomp from a shell where the tool works.
- **`cfr` is listed but never runs**: CFR ships as a jar. Create a `cfr` launcher (an `.exe` on Windows, since `.bat`
  and `.cmd` are refused) that runs `java -jar cfr.jar <args>`, and put it on `PATH`. A launcher this small, written in Rust
  in about 20 lines, was used for the verification. Enabling fails with "engine program 'cfr' was not found" until the launcher is on `PATH`.
- **GUI window does not open or is blank**: it draws with OpenGL. Update the graphics driver, or on a remote
  desktop / virtual machine enable 3D acceleration.
- **Traditional Chinese is greyed out in View > Language**: no font with Chinese glyphs was found. Install one (Windows has Microsoft JhengHei; on Linux, Noto Sans CJK, e.g. `fonts-noto-cjk` on Debian/Ubuntu) or set `OMNIDECOMP_CJK_FONT=<path>[,<face index>]`. Chinese text shows as empty boxes only if the named font lacks the glyphs.
- **The file dialog does nothing on Linux**: it uses the desktop portal (xdg-desktop-portal). Install the portal
  for your desktop, or start the GUI with a path argument or drop a file onto the window.
- **Wrong or odd output for a damaged file**: damaged inputs yield an error or partial listings, never guessed content.
  Compare with `omnidecomp info`.
- **Linux: "version `GLIBC_2.39' not found"**: the system is older than Ubuntu 24.04. Build from source.
- **Windows SmartScreen warns**: the binaries are not code-signed. Check the SHA-256 against `SHA256SUMS` first.

When reporting a problem, include the output of `omnidecomp --version`, the full `error[...]` line, the exit
code, and `VERSION.json`. Do not attach files you are not allowed to share.
