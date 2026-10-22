# Plugin API (version 1)

Phase 4. A plugin is a **directory with a `plugin.json`**. Nothing from a plugin is ever loaded into the
OmniDecomp process: there are no shared libraries, scripts or in-process hooks. The only thing a plugin can
do is describe an external **decompiler program** that OmniDecomp starts as a child process, and only when
the user has enabled the plugin *and* passed `--allow-external-exec` for that run.

Built-in capabilities (`format-pe`, `format-elf`, `format-macho`, `arch-x86`, `arch-arm64`,
`runtime-dotnet`, `runtime-java`) appear in the same list and can be disabled and enabled the same way.

## Commands

```
omnidecomp plugins list [--format json]
omnidecomp plugins enable <id>
omnidecomp plugins disable <id>
omnidecomp decompile <file> --engine <id> --allow-external-exec [--output path] [--format json] [--max-output-mb 16]
```

Global flags: `--plugins-dir` (default: `plugins` next to the executable, or `$OMNIDECOMP_PLUGINS_DIR`) and
`--state-file` (default: `%APPDATA%\OmniDecomp\plugins.json` or `~/.config/OmniDecomp/plugins.json`, or
`$OMNIDECOMP_STATE_FILE`).

Exit codes: 19 unknown plugin, 20 plugin disabled, 21 incompatible (API/host version, or files changed since
enable), 22 external engine failed or not found. Unknown decompiler id is 15; unsupported input is 12.

## `plugin.json`

| field | rules |
|---|---|
| `id` | 1-64 chars of `a-z 0-9 . _ -`, must equal the directory name, must not be a built-in id |
| `name`, `description`, `source` | text, length-limited; shown as plain text |
| `version` | `major.minor.patch` |
| `api_version` | must be `1` |
| `min_host_version` | optional `major.minor.patch`; the host must be at least this |
| `license` | **required** SPDX id or license name of the plugin/engine |
| `kind` | `decompiler` (the only kind) |
| `runtimes` | non-empty subset of `dotnet`, `java` |
| `command` | a bare program name (looked up on PATH) or a relative path inside the plugin directory; no `..`, no absolute paths, no backslashes, no leading `-`. On Windows only `.exe`/`.com` (batch files are refused because `cmd.exe` re-parses arguments) |
| `args` | up to 16 argv entries, no shell. `{input}` is the only placeholder and must appear |

Unknown fields are rejected. `plugin.json` is limited to 64 KiB. A bad plugin shows up as `invalid` or
`incompatible` in `plugins list` with a reason; it never breaks other plugins or other commands.

## Trust model

- **Explicit enable.** External plugins start disabled. The enabled state lives in the per-user state file,
  not in the plugins directory, so a directory that arrives from elsewhere cannot enable itself.
- **Pinned files.** `enable` records the SHA-256 of `plugin.json` and of the resolved engine program. If either
  changes, the plugin shows as disabled (manifest) or the run is refused with exit 21 (program) until it is
  enabled again.
- **Consent per run.** `decompile` never starts a program without `--allow-external-exec`.
- **Child process limits.** No shell; the input is one argv entry; stdin is closed; the environment is cleared
  except PATH, SystemRoot, TEMP/TMP/TMPDIR, HOME/USERPROFILE, JAVA_HOME and DOTNET_ROOT; the job timeout and
  Ctrl+C kill the child; output is capped (default 16 MiB, `--max-output-mb`) and the child is killed when
  it is exceeded. The analysed file is never executed by OmniDecomp.
- **Untrusted output.** Decompiler text is shown as plain text; control characters other than newline and tab
  are replaced with `?`. Output files go through the same path validation as reports.
- **Not provided:** OS-level sandboxing (no network, file-system or memory isolation). A decompiler is a
  third-party program running with your user rights. Enable only engines you trust.

## Writing a plugin

1. Create `plugins/<id>/plugin.json` with a `license` and `source`.
2. Put a `NOTICE.md` next to it that states the license of the manifest and of the engine, and where to get the engine.
3. Make sure the engine prints the decompiled source on stdout and exits 0 on success.
4. Add the id to the shipped-plugin test (`every_shipped_plugin_manifest_is_valid_licensed_and_has_a_notice`
   walks `plugins/*` automatically).

Shipped examples: `plugins/ilspycmd` (.NET) and `plugins/cfr` (Java). They are manifests only; the engines are
not bundled.

## Using plugins from the desktop UI
The GUI shares the CLI's plugin folder and state file (`omnidecomp_plugins::Locations`), so a plugin enabled in one is enabled in the other.

- **Plugins tab**: lists built-in and external plugins with version, status, license and source. Built-ins can be disabled and re-enabled at once. Enabling an external plugin shows a confirmation that explains the fingerprinting and that the program runs with your rights; nothing is saved until you confirm.
- **Decompile tab**: uses the path in the File box (a .NET assembly or a Java `.class`; a `.class` does not need to open as a binary). *Decompile this file* first runs every check without starting anything (runtime detection, built-in runtime plugin, plugin enabled, manifest and program hashes). Then a window shows the exact program and arguments; *Allow and run* is the per-run consent that `--allow-external-exec` gives on the command line. It is never remembered, so every run asks again. The program is re-verified when it starts. A running decompile can be cancelled (the child process is killed).
- Output is shown as plain text in a scrolling list, labelled as untrusted output of an external program; *Copy all* puts it on the clipboard. Limits are the CLI defaults except time: 300 s and 16 MiB.
- Disabling a format/architecture built-in blocks opening such files in the GUI, as it does on the command line.

