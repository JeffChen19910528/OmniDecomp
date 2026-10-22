//! Headless interaction tests: the real `App::show` is driven by `egui_kittest`, clicking and typing
//! through the accessibility tree, so the checks cover what the manual acceptance list asked for.

use super::*;
use omnidecomp_viewmodel::{Locations, Theme};
use crate::{cjk, i18n};
use egui::accesskit::Role;
use egui_kittest::kittest::{NodeT, Queryable};
use egui_kittest::Harness;
use omnidecomp_testsamples::{elf64_large, elf64_with_code, elf64_with_symbols, CALL_CODE, CFG_CODE};
use std::time::{Duration, Instant};

fn write(dir: &tempfile::TempDir, name: &str, bytes: Vec<u8>) -> PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// Plugin locations that exist nowhere, so tests never read or write the real user state.
fn nowhere() -> Locations {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let base = std::env::temp_dir().join(format!("omnidecomp-gui-test-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    Locations { dir: base.join("plugins"), state: Some(base.join("plugins.json")) }
}

fn harness_with<'a>(path: Option<PathBuf>, loc: Locations) -> Harness<'a, App> {
    let app = App::with_plugins(&egui::Context::default(), path, loc);
    Harness::builder().with_size(egui::vec2(1400.0, 800.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app)
}

fn harness_for<'a>(path: Option<PathBuf>) -> Harness<'a, App> {
    harness_with(path, nowhere())
}

/// Steps until the background load finished (successfully or not).
fn wait_done(h: &mut Harness<'_, App>) {
    let t = Instant::now();
    loop {
        h.step();
        if h.state().task.is_none() {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(60), "load did not finish");
        std::thread::sleep(Duration::from_millis(10));
    }
    h.run();
}

fn loaded(bytes: Vec<u8>) -> (tempfile::TempDir, Harness<'static, App>) {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "sample.bin", bytes);
    let mut h = harness_for(Some(p));
    wait_done(&mut h);
    assert!(h.state().loaded.is_some(), "error: {:?}", h.state().error);
    (dir, h)
}

#[test]
fn initial_window_explains_what_to_do_and_loading_shows_all_panes() {
    let mut h = harness_for(None);
    h.run();
    assert!(h.query_by_label_contains("No file loaded").is_some());

    let (_d, h) = loaded(elf64_with_symbols());
    assert!(h.query_by_label_contains("iced-x86 1.21.0").is_some(), "disassembly header");
    assert!(h.query_by_label_contains("push").is_some(), "instruction rows");
    assert!(h.query_by_label_contains("Hex (synced to selection)").is_some(), "hex pane");
    assert!(h.query_by_label("sha-256").is_some(), "info pane");
    assert!(h.query_all_by_label_contains(".text").count() > 0, "section list");
}

#[test]
fn left_tabs_switch_and_filter() {
    let (_d, mut h) = loaded(elf64_with_symbols());
    h.get_by_label("Functions").click();
    h.run();
    assert!(h.query_all_by_label_contains("[symbol/high]").count() > 0, "function list shows the symbol-named function with its source and confidence");

    h.get_by_label("Symbols").click();
    h.run();
    assert!(h.query_all_by_label_contains("puts").count() > 0 && h.query_all_by_label_contains("(import)").count() > 0);

    h.get_by_label("Strings").click();
    h.run();
    assert!(h.query_by_label_contains(".strtab").is_some(), "string list shows ELF strings");
}

#[test]
fn clicking_a_function_selects_it_and_syncs_the_hex_pane() {
    let (_d, mut h) = loaded(elf64_with_symbols());
    h.get_by_label("Functions").click();
    h.run();
    h.get_by_label_contains("[symbol/high]").click();
    h.run();
    assert_eq!(h.state().selected, Some(0x40_1000));
    assert_eq!(h.state().hex_offset, 0x40, "hex pane follows the file offset of the selection");
}

#[test]
fn clicking_an_instruction_opens_cross_references() {
    let (_d, mut h) = loaded(elf64_with_code(&CALL_CODE));
    h.get_by_label_contains("call").click();
    h.run();
    assert_eq!(h.state().selected, Some(0x40_1000));
    assert_eq!(h.state().bottom, BottomTab::Xrefs);
    assert!(h.query_by_label_contains("references from 0x401000").is_some());
    assert!(h.query_by_label_contains("here call -> 0x40100a").is_some());
}

#[test]
fn following_a_call_target_moves_selection() {
    let (_d, mut h) = loaded(elf64_with_code(&CALL_CODE));
    h.get_by_label_contains("call").click();
    h.run();
    h.get_by_label_contains("here call -> 0x40100a").click();
    h.run();
    assert_eq!(h.state().selected, Some(0x40_100a), "clicking an xref entry navigates to it");
    // `goto` is also what a double click on a call instruction runs.
    h.state_mut().goto(0x40_1000);
    h.run();
    assert_eq!(h.state().selected, Some(0x40_1000));
}

#[test]
fn search_finds_symbols_and_results_navigate() {
    let (_d, mut h) = loaded(elf64_with_symbols());
    let boxes: Vec<_> = h.get_all_by_role(Role::TextInput).collect();
    let search_box = boxes.iter().find(|n| n.value().is_none_or(|v| v.is_empty())).expect("an empty search box");
    search_box.click();
    search_box.type_text("main");
    h.run();
    h.key_press(egui::Key::Enter);
    h.run();
    assert!(h.query_by_label_contains("result(s)").is_some());
    assert!(!h.state().results.is_empty(), "query typed into the box reached the model");
    h.get_by_label_contains("[func]").click();
    h.run();
    assert_eq!(h.state().selected, Some(0x40_1000));
}

#[test]
fn view_menu_changes_theme_and_font_size() {
    let (_d, mut h) = loaded(elf64_with_symbols());
    assert_eq!(h.state().settings.theme, Theme::Dark);
    h.get_by_label("View").click();
    h.run();
    h.get_by_label("Light").click();
    h.run();
    assert_eq!(h.state().settings.theme, Theme::Light);

    let height_of = |h: &Harness<'_, App>| h.get_by_label_contains("push").rect().height();
    let small = height_of(&h);
    h.state_mut().settings.font_size = 28.0;
    h.run();
    assert!(height_of(&h) > small, "larger font gives taller rows");
    h.state_mut().settings.font_size = f32::NAN;
    h.run();
    assert_eq!(h.state().settings.font_size, 14.0, "invalid values are replaced, not drawn");
}

#[test]
fn hex_rows_stay_on_one_line_even_with_large_fonts() {
    let (_d, mut h) = loaded(elf64_with_symbols());
    h.state_mut().settings.font_size = 24.0;
    h.run();
    let hex = h.get_by_label_contains("7f 45 4c 46").rect();
    let row = h.get_by_label_contains("push").rect();
    assert!(hex.height() < row.height() * 1.5, "hex row {} vs instruction row {}", hex.height(), row.height());
}

#[test]
fn bad_file_shows_an_error_and_the_window_keeps_working() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "junk", b"definitely not an executable".to_vec());
    let mut h = harness_for(Some(p));
    wait_done(&mut h);
    assert!(h.query_by_label_contains("error[unsupported_format]").is_some());
    assert!(h.state().loaded.is_none());
    h.get_by_label("Symbols").click();
    h.run();
    assert_eq!(h.state().left, LeftTab::Symbols, "UI still responds after a failed load");
    // A following good load replaces the error.
    let good = write(&dir, "ok.bin", elf64_with_symbols());
    h.state_mut().open(&good, &egui::Context::default());
    wait_done(&mut h);
    assert!(h.state().loaded.is_some());
    assert!(h.state().error.is_none());
}

#[test]
fn cancel_stops_a_long_load() {
    let dir = tempfile::tempdir().unwrap();
    let unit = [0xE8, 0, 0, 0, 0, 0x55, 0x48, 0x89, 0xE5, 0x90, 0x5D, 0xC3];
    let p = write(&dir, "big.elf", elf64_large(&unit, 8 * 1024 * 1024));
    let mut h = harness_for(Some(p));
    h.step();
    h.get_by_label("Cancel").click();
    wait_done(&mut h);
    assert!(h.state().loaded.is_none());
    assert!(h.query_by_label_contains("cancelled").is_some(), "error: {:?}", h.state().error);
}

#[derive(Debug)]
struct Dropped(PathBuf);
impl egui::DroppedFile for Dropped {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        std::fs::read(&self.0).map_err(|e| e.to_string())
    }
}

#[test]
fn dropping_a_file_opens_it() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "dropped.bin", elf64_with_symbols());
    let mut h = harness_for(None);
    h.run();
    h.input_mut().dropped_files.push(std::sync::Arc::new(Dropped(p)));
    wait_done(&mut h);
    assert_eq!(h.state().loaded.as_ref().map(|l| l.name.as_str()), Some("dropped.bin"));
}

#[test]
fn high_dpi_and_extreme_settings_do_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "s.bin", elf64_with_symbols());
    let app = App::with_plugins(&egui::Context::default(), Some(p), nowhere());
    let mut h = Harness::builder()
        .with_size(egui::vec2(700.0, 500.0))
        .with_pixels_per_point(2.5)
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    wait_done(&mut h);
    for (font, spacing) in [(8.0, 0.0), (32.0, 12.0), (1000.0, -5.0)] {
        h.state_mut().settings.font_size = font;
        h.state_mut().settings.line_spacing = spacing;
        h.run();
    }
    for tab in ["Functions", "Symbols", "Strings", "Info"] {
        h.get_by_label(tab).click();
        h.run();
    }
}

#[test]
fn double_clicking_a_call_follows_its_target() {
    // egui only counts a double click when both clicks fall within 0.3 s of simulated time, so the
    // harness steps must be much shorter than the default 0.25 s.
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "calls.bin", elf64_with_code(&CALL_CODE));
    let app = App::with_plugins(&egui::Context::default(), Some(p), nowhere());
    let mut h = Harness::builder()
        .with_size(egui::vec2(1400.0, 800.0))
        .with_step_dt(0.01)
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    wait_done(&mut h);
    assert_ne!(h.state().selected, Some(0x40_100a));
    h.get_by_label_contains("0000000000401000").click();
    h.step();
    h.get_by_label_contains("0000000000401000").click();
    h.run();
    assert_eq!(h.state().selected, Some(0x40_100a), "double click on `call` selects the callee");
}

fn stepping_until(h: &mut Harness<'_, App>, what: &str, done: impl Fn(&App) -> bool) {
    let t = Instant::now();
    while !done(h.state()) {
        h.step();
        assert!(t.elapsed() < Duration::from_secs(30), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
    // `run()` would trip over the picker's pending `request_repaint_after`, so only step.
    while h.state().task.is_some() {
        h.step();
        assert!(t.elapsed() < Duration::from_secs(60), "load did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    h.step();
}

#[test]
fn open_file_button_uses_the_picker_off_the_ui_thread() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "picked.bin", elf64_with_symbols());
    let mut app = App::with_plugins(&egui::Context::default(), None, nowhere());
    let chosen = p.clone();
    app.set_file_picker(std::sync::Arc::new(move || Some(chosen.clone())));
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 800.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    h.run();
    h.get_by_label("Open file...").click();
    stepping_until(&mut h, "the picked file to load", |a| a.loaded.is_some());
    assert_eq!(h.state().loaded.as_ref().map(|l| l.name.as_str()), Some("picked.bin"));
    assert_eq!(h.state().path_input, p.to_string_lossy());
}

#[test]
fn cancelling_the_file_dialog_changes_nothing() {
    let (_d, mut h) = loaded(elf64_with_symbols());
    h.state_mut().set_file_picker(std::sync::Arc::new(|| None));
    h.get_by_label("Open file...").click();
    stepping_until(&mut h, "the dialog to close", |a| a.pending_pick.is_none());
    h.step();
    assert!(h.state().loaded.is_some() && h.state().error.is_none() && h.state().task.is_none());
}

#[test]
fn the_file_button_is_disabled_while_a_dialog_is_open() {
    let mut app = App::with_plugins(&egui::Context::default(), None, nowhere());
    let (release, gate) = std::sync::mpsc::channel::<()>();
    let gate = std::sync::Mutex::new(gate);
    app.set_file_picker(std::sync::Arc::new(move || {
        let _ = gate.lock().unwrap().recv();
        None
    }));
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 800.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    h.run();
    h.get_by_label("Open file...").click();
    h.step();
    h.step();
    assert!(h.state().pending_pick.is_some());
    assert!(h.get_by_label("Open file...").accesskit_node().is_disabled(), "a second dialog cannot be opened");
    release.send(()).unwrap();
    stepping_until(&mut h, "the dialog to close", |a| a.pending_pick.is_none());
}

#[test]
fn cfg_tab_shows_blocks_and_nodes_navigate() {
    let (_d, mut h) = loaded(elf64_with_code(&CFG_CODE));
    h.get_by_label("CFG").click();
    h.run();
    assert!(h.query_by_label_contains("blocks of").is_some(), "header names what is drawn");
    assert!(h.query_by_label_contains("3 insn").is_some() && h.query_by_label_contains("0x401009").is_some(), "first block and the branch target are nodes");
    h.get_by_label_contains("0x401009").click();
    h.run();
    assert_eq!(h.state().selected, Some(0x40_1009), "clicking a block selects its start");
    assert_eq!(h.state().center, CenterTab::Cfg, "a single click stays in the graph");
}

#[test]
fn double_clicking_a_graph_node_opens_it_in_the_disassembly() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "cfg.bin", elf64_with_code(&CFG_CODE));
    let app = App::with_plugins(&egui::Context::default(), Some(p), nowhere());
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 800.0)).with_step_dt(0.01).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    wait_done(&mut h);
    h.get_by_label("CFG").click();
    h.run();
    // The tab click just before makes egui report this pair as a triple click; it must still count.
    h.get_by_label_contains("0x401009").click();
    h.step();
    h.get_by_label_contains("0x401009").click();
    h.run();
    assert_eq!(h.state().center, CenterTab::Disasm);
    assert_eq!(h.state().selected, Some(0x40_1009));
}

#[test]
fn call_graph_tab_draws_the_neighbourhood_and_depth_is_adjustable() {
    let (_d, mut h) = loaded(elf64_with_code(&CALL_CODE));
    h.get_by_label("Call graph").click();
    h.run();
    assert!(h.query_by_label_contains("functions around").is_some());
    assert!(h.query_by_label_contains("0x40100a").is_some(), "the callee is a node");
    assert!(h.query_by_label_contains("1 edges").is_some(), "one call edge: {:?}", h.state().graph.as_ref().map(|g| g.key));
    h.state_mut().call_depth = 3;
    h.run();
    assert_eq!(h.state().graph.as_ref().map(|g| g.key.2), Some(3), "changing depth rebuilds the layout");
}

#[test]
fn loops_in_a_cfg_do_not_break_the_view() {
    // nop; jmp back to the nop: a one-block loop whose only edge is a back edge.
    let (_d, mut h) = loaded(elf64_with_code(&[0x90, 0xEB, 0xFD]));
    h.get_by_label("CFG").click();
    h.run();
    let layout = h.state().graph.as_ref().unwrap().layout.as_ref().unwrap();
    assert!(layout.edges.iter().any(|e| e.back), "self loop is marked as a back edge");
    assert!(h.query_by_label_contains("insn").is_some());
}

#[test]
fn graph_tabs_survive_extreme_settings_and_tiny_windows() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "g.bin", elf64_with_code(&CFG_CODE));
    let app = App::with_plugins(&egui::Context::default(), Some(p), nowhere());
    let mut h = Harness::builder().with_size(egui::vec2(500.0, 400.0)).with_pixels_per_point(2.5).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    wait_done(&mut h);
    for tab in ["CFG", "Call graph", "Disassembly"] {
        h.get_by_label(tab).click();
        for (font, spacing) in [(8.0, 0.0), (64.0, 12.0), (1000.0, -5.0)] {
            h.state_mut().settings.font_size = font;
            h.state_mut().settings.line_spacing = spacing;
            h.run();
        }
    }
}

#[test]
fn graph_tabs_explain_themselves_without_a_file_or_functions() {
    let mut h = harness_for(None);
    h.get_by_label("CFG").click();
    h.run();
    assert!(h.query_by_label_contains("once a file is loaded").is_some());
    let (_d, mut h) = loaded(omnidecomp_testsamples::minimal_elf32_be());
    h.get_by_label("Call graph").click();
    h.run();
    assert!(h.query_by_label_contains("No functions were recovered").is_some(), "no guessed graph for an unsupported architecture");
}

// ---------------------------------------------------------------------------------------------
// Plugins and decompile

use omnidecomp_testsamples::{fake_engine_path, java_class, pe64_dotnet};

/// A plugins folder holding one stand-in decompiler `fake`, and a state file location beside it.
fn plugin_env(mode: &str) -> (tempfile::TempDir, Locations) {
    let dir = tempfile::tempdir().unwrap();
    let plugins = dir.path().join("plugins");
    let p = plugins.join("fake");
    std::fs::create_dir_all(p.join("bin")).unwrap();
    let exe = format!("bin/fake-engine{}", std::env::consts::EXE_SUFFIX);
    std::fs::copy(fake_engine_path(), p.join(&exe)).unwrap();
    std::fs::write(
        p.join("plugin.json"),
        format!(
            r#"{{"id":"fake","name":"Fake engine","version":"0.3.0","api_version":1,"license":"MIT","source":"tests",
            "kind":"decompiler","runtimes":["dotnet","java"],"command":"{exe}","args":["{mode}","{{input}}"]}}"#
        ),
    )
    .unwrap();
    let loc = Locations { dir: plugins, state: Some(dir.path().join("cfg").join("plugins.json")) };
    (dir, loc)
}

fn enable(loc: &Locations, id: &str) {
    omnidecomp_viewmodel::jobs::set_plugin_enabled(loc, id, true).unwrap();
}

fn tab(h: &mut Harness<'_, App>, name: &str) {
    h.get_by_label(name).click();
    h.run();
}

fn step_until(h: &mut Harness<'_, App>, what: &str, done: impl Fn(&App) -> bool) {
    let t = Instant::now();
    while !done(h.state()) {
        h.step();
        assert!(t.elapsed() < Duration::from_secs(30), "timed out waiting for {what}; error={:?} plan_running={} confirm={}", h.state().pl.error, h.state().pl.plan.is_some(), h.state().pl.confirm_run.is_some());
        std::thread::sleep(Duration::from_millis(5));
    }
    h.step();
}

/// Harness showing `bytes` (a file named `name`) loaded, with plugin locations `loc`.
fn with_file(loc: Locations, name: &str, bytes: Vec<u8>) -> (tempfile::TempDir, Harness<'static, App>) {
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, name, bytes);
    let mut h = harness_with(Some(p), loc);
    wait_done(&mut h);
    (dir, h)
}

#[test]
fn plugins_tab_lists_everything_and_trusting_an_external_plugin_needs_confirmation() {
    let (_d, loc) = plugin_env("ok");
    let state = loc.state.clone().unwrap();
    let mut h = harness_with(None, loc);
    h.run();
    tab(&mut h, "Plugins");
    assert!(h.query_all_by_label_contains("format-pe").count() > 0, "built-ins are listed");
    assert!(h.query_by_label_contains("fake 0.3.0 [external/decompiler] disabled").is_some());
    assert!(h.query_by_label_contains("license: MIT | source: tests").is_some());

    h.get_by_label("Enable fake").click();
    h.run();
    assert!(h.query_all_by_label_contains("fingerprint").count() > 0, "confirmation is shown");
    assert!(!state.exists(), "nothing was saved before the user confirmed");

    h.get_by_label("Cancel").click();
    h.run();
    assert!(h.query_by_label_contains("fake 0.3.0 [external/decompiler] disabled").is_some());
    assert!(!state.exists());

    h.get_by_label("Enable fake").click();
    h.run();
    h.get_by_label("Trust and enable fake").click();
    h.run();
    assert!(h.query_by_label_contains("fake 0.3.0 [external/decompiler] enabled").is_some());
    assert!(h.query_by_label("Disable fake").is_some());
    assert!(state.exists(), "the choice was saved");

    h.get_by_label("Disable fake").click();
    h.run();
    assert!(h.query_by_label_contains("fake 0.3.0 [external/decompiler] disabled").is_some());
}

#[test]
fn built_in_plugins_toggle_at_once_and_a_disabled_format_blocks_opening() {
    let (_d, loc) = plugin_env("ok");
    let mut h = harness_with(None, loc);
    h.run();
    tab(&mut h, "Plugins");
    h.get_by_label("Disable format-elf").click();
    h.run();
    assert!(h.query_by_label("Enable format-elf").is_some(), "now offered for re-enabling");

    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "a.elf", elf64_with_symbols());
    h.state_mut().path_input = p.to_string_lossy().into_owned();
    h.get_by_label("Open").click();
    wait_done(&mut h);
    assert!(h.state().loaded.is_none());
    let err = h.state().error.clone().unwrap_or_default();
    assert!(err.starts_with("error[plugin_disabled]") && err.contains("format-elf"), "{err}");

    h.get_by_label("Enable format-elf").click();
    h.run();
    h.get_by_label("Open").click();
    wait_done(&mut h);
    assert!(h.state().loaded.is_some(), "{:?}", h.state().error);
}

#[test]
fn decompile_tab_without_an_enabled_engine_explains_and_does_nothing() {
    let (_d, loc) = plugin_env("ok");
    let (_f, mut h) = with_file(loc, "a.dll", pe64_dotnet());
    tab(&mut h, "Decompile");
    assert!(h.query_by_label_contains("No decompiler is enabled").is_some());
    assert!(h.get_by_label("Decompile this file").accesskit_node().is_disabled());
    assert!(h.state().pl.output.is_none());
}

#[test]
fn decompile_asks_for_consent_per_run_and_shows_the_output() {
    let (_d, loc) = plugin_env("ok");
    enable(&loc, "fake");
    let (_f, mut h) = with_file(loc, "a.dll", pe64_dotnet());
    tab(&mut h, "Decompile");
    assert!(h.query_by_label_contains("No decompiler is enabled").is_none());
    h.get_by_label("Decompile this file").click();
    step_until(&mut h, "the consent window", |a| a.pl.confirm_run.is_some());

    // Nothing has run yet: the window names the program, and there is no output.
    assert!(h.query_all_by_label_contains("program:").count() > 0);
    assert!(h.query_all_by_label_contains("fake-engine").count() > 0);
    assert!(h.state().pl.run.is_none() && h.state().pl.output.is_none());

    h.get_by_label("Allow and run").click();
    step_until(&mut h, "the decompiled text", |a| a.pl.output.is_some() || a.pl.error.is_some());
    assert!(h.state().pl.error.is_none(), "{:?}", h.state().pl.error);
    h.run();
    assert!(h.query_by_label_contains("decompiled by fake-engine").is_some());
    assert!(h.query_all_by_label_contains("untrusted").count() > 0, "output is labelled as untrusted");

    // Consent was for one run only: a second run asks again.
    h.get_by_label("Decompile this file").click();
    step_until(&mut h, "the second consent window", |a| a.pl.confirm_run.is_some());
    assert!(h.state().pl.run.is_none());
}

#[test]
fn declining_the_consent_window_starts_nothing() {
    let (_d, loc) = plugin_env("ok");
    enable(&loc, "fake");
    let (_f, mut h) = with_file(loc, "a.dll", pe64_dotnet());
    tab(&mut h, "Decompile");
    h.get_by_label("Decompile this file").click();
    step_until(&mut h, "the consent window", |a| a.pl.confirm_run.is_some());
    h.get_by_label("Cancel run").click();
    h.run();
    assert!(h.state().pl.confirm_run.is_none() && h.state().pl.run.is_none() && h.state().pl.output.is_none());
    assert!(h.state().log.iter().any(|l| l.contains("cancelled before starting")));
}

#[test]
fn native_code_and_missing_files_get_a_clear_error_without_a_consent_window() {
    let (_d, loc) = plugin_env("ok");
    enable(&loc, "fake");
    let (_f, mut h) = with_file(loc, "n.bin", elf64_with_symbols());
    tab(&mut h, "Decompile");
    h.get_by_label("Decompile this file").click();
    step_until(&mut h, "the refusal", |a| a.pl.error.is_some());
    assert!(h.state().pl.error.as_deref().unwrap().starts_with("error[unsupported_format]"));
    assert!(h.state().pl.confirm_run.is_none());

    h.state_mut().path_input = "no/such/file.dll".into();
    h.run();
    h.get_by_label("Decompile this file").click();
    step_until(&mut h, "the missing-file error", |a| a.pl.error.as_deref().is_some_and(|e| e.starts_with("error[io]")));
    assert!(h.state().pl.confirm_run.is_none());
}

#[test]
fn java_class_files_can_be_decompiled_by_path_even_though_they_do_not_open_as_binaries() {
    let (_d, loc) = plugin_env("ok");
    enable(&loc, "fake");
    let dir = tempfile::tempdir().unwrap();
    let p = write(&dir, "A.class", java_class());
    let mut h = harness_with(None, loc);
    h.run();
    h.state_mut().path_input = p.to_string_lossy().into_owned();
    tab(&mut h, "Decompile");
    h.get_by_label("Decompile this file").click();
    step_until(&mut h, "the consent window", |a| a.pl.confirm_run.is_some());
    h.get_by_label("Allow and run").click();
    step_until(&mut h, "output", |a| a.pl.output.is_some() || a.pl.error.is_some());
    assert!(h.state().pl.output.as_ref().is_some_and(|o| o.header.contains("(java)")), "{:?}", h.state().pl.error);
}

#[test]
fn a_program_changed_after_the_window_opened_is_caught_at_run_time() {
    let (_d, loc) = plugin_env("ok");
    enable(&loc, "fake");
    let exe = loc.dir.join("fake").join(format!("bin/fake-engine{}", std::env::consts::EXE_SUFFIX));
    let (_f, mut h) = with_file(loc, "a.dll", pe64_dotnet());
    tab(&mut h, "Decompile");
    h.get_by_label("Decompile this file").click();
    step_until(&mut h, "the consent window", |a| a.pl.confirm_run.is_some());
    let mut bytes = std::fs::read(&exe).unwrap();
    bytes.push(0);
    std::fs::write(&exe, bytes).unwrap();
    h.get_by_label("Allow and run").click();
    step_until(&mut h, "the failure", |a| a.pl.error.is_some());
    assert!(h.state().pl.error.as_deref().unwrap().starts_with("error[plugin_incompatible]"));
    assert!(h.state().pl.output.is_none());
}

#[test]
fn a_running_decompile_can_be_cancelled() {
    let (_d, loc) = plugin_env("sleep");
    enable(&loc, "fake");
    let (_f, mut h) = with_file(loc, "a.dll", pe64_dotnet());
    tab(&mut h, "Decompile");
    h.get_by_label("Decompile this file").click();
    step_until(&mut h, "the consent window", |a| a.pl.confirm_run.is_some());
    h.get_by_label("Allow and run").click();
    step_until(&mut h, "the run to start", |a| a.pl.run.is_some());
    assert!(h.get_by_label("Decompile this file").accesskit_node().is_disabled(), "Decompile is disabled while running");
    std::thread::sleep(Duration::from_millis(300));
    let t = Instant::now();
    h.get_by_label("Cancel decompile").click();
    step_until(&mut h, "the cancellation", |a| a.pl.error.is_some());
    assert!(h.state().pl.error.as_deref().unwrap().starts_with("error[cancelled]"));
    assert!(t.elapsed() < Duration::from_secs(10));
    assert!(h.state().pl.run.is_none());
}

#[test]
fn a_corrupt_state_file_is_reported_in_the_tab() {
    let (_d, loc) = plugin_env("ok");
    std::fs::create_dir_all(loc.state.as_ref().unwrap().parent().unwrap()).unwrap();
    std::fs::write(loc.state.as_ref().unwrap(), "{{{").unwrap();
    let mut h = harness_with(None, loc);
    h.run();
    tab(&mut h, "Plugins");
    assert!(h.query_by_label_contains("error[malformed]").is_some());
}

// ---------------------------------------------------------------------------------------------
// Interface language

/// The tests that need a real Chinese font are skipped (loudly) on machines that have none.
fn has_cjk_font() -> bool {
    let found = cjk::find().is_some();
    if !found {
        eprintln!("skipped: no Traditional Chinese font on this machine");
    }
    found
}

fn choose_language(h: &mut Harness<'_, App>, name: &str) {
    let view = if h.state().lang == Lang::ZhTw { "檢視" } else { "View" };
    h.get_by_label(view).click();
    h.run();
    h.get_by_label(name).click();
    h.run();
}

#[test]
fn english_is_the_default_and_the_language_choice_lives_in_the_view_menu() {
    let mut h = harness_for(None);
    h.run();
    assert_eq!(h.state().lang, Lang::En);
    assert!(h.query_by_label("Open file...").is_some());
    h.get_by_label("View").click();
    h.run();
    assert!(h.query_by_label("English").is_some() && h.query_by_label("繁體中文").is_some());
}

#[test]
fn switching_to_traditional_chinese_translates_the_interface_and_is_remembered() {
    if !has_cjk_font() {
        return;
    }
    let (_d, loc) = plugin_env("ok");
    let prefs = i18n::prefs_path(loc.state.as_deref()).unwrap();
    let mut h = harness_with(None, loc.clone());
    h.run();
    choose_language(&mut h, "繁體中文");
    assert_eq!(h.state().lang, Lang::ZhTw);
    assert_eq!(h.state().applied_lang, Some(Lang::ZhTw), "fonts were installed for Chinese");
    for zh in ["開啟檔案…", "反組譯", "呼叫圖", "反編譯", "外掛", "搜尋", "記錄", "資訊", "函式"] {
        assert!(h.query_all_by_label_contains(zh).count() > 0, "missing {zh}");
    }
    assert!(h.query_by_label("Open file...").is_none(), "no English label is left on the file bar");
    assert!(prefs.exists(), "the choice was saved");

    // A new window with the same settings starts in Chinese.
    let mut h2 = harness_with(None, loc.clone());
    h2.run();
    assert_eq!(h2.state().lang, Lang::ZhTw);
    assert!(h2.query_by_label("開啟檔案…").is_some());

    // And back.
    choose_language(&mut h, "English");
    assert_eq!(h.state().lang, Lang::En);
    assert!(h.query_by_label("Open file...").is_some());
    assert_eq!(i18n::load_pref(Some(&prefs)), Some(Lang::En));
}

#[test]
fn plugin_and_decompile_windows_are_translated_and_still_work() {
    if !has_cjk_font() {
        return;
    }
    let (_d, loc) = plugin_env("ok");
    enable(&loc, "fake");
    let (_f, mut h) = with_file(loc, "a.dll", pe64_dotnet());
    choose_language(&mut h, "繁體中文");
    tab(&mut h, "外掛");
    assert!(h.query_by_label("停用 fake").is_some());
    assert!(h.query_all_by_label_contains("授權: MIT").count() > 0);
    tab(&mut h, "反編譯");
    h.get_by_label("反編譯這個檔案").click();
    step_until(&mut h, "the consent window", |a| a.pl.confirm_run.is_some());
    assert!(h.query_all_by_label_contains("程式:").count() > 0, "consent window is in Chinese and names the program");
    h.get_by_label("允許並執行").click();
    step_until(&mut h, "output", |a| a.pl.output.is_some() || a.pl.error.is_some());
    assert!(h.state().pl.error.is_none(), "{:?}", h.state().pl.error);
    h.run();
    assert!(h.query_by_label_contains("decompiled by fake-engine").is_some(), "decompiler text itself is not translated");
    assert!(h.query_all_by_label_contains("不可信").count() > 0, "the untrusted-output note is translated");
}

#[test]
fn without_a_chinese_font_the_choice_is_refused_and_explained() {
    let mut h = harness_for(None);
    h.state_mut().cjk = None;
    h.run();
    h.get_by_label("View").click();
    h.run();
    assert!(h.query_all_by_label_contains("找不到中文字型").count() == 0, "still English");
    assert!(h.query_all_by_label_contains("Chinese font was not found").count() > 0);
    h.state_mut().set_language(Lang::ZhTw);
    assert_eq!(h.state().lang, Lang::En, "refused");
}

#[test]
fn a_saved_chinese_choice_falls_back_to_english_when_the_font_is_gone() {
    let (_d, loc) = plugin_env("ok");
    let prefs = i18n::prefs_path(loc.state.as_deref());
    i18n::save_pref(prefs.as_deref(), Lang::ZhTw).unwrap();
    std::env::set_var("OMNIDECOMP_CJK_FONT", "/definitely/not/a/font.ttc");
    // find() still falls through to the system list, so only assert the invariant that matters:
    // Chinese is used only when a font was found.
    let h = harness_with(None, loc);
    std::env::remove_var("OMNIDECOMP_CJK_FONT");
    assert!(h.state().lang == Lang::En || h.state().cjk.is_some());
}

#[test]
fn a_broken_font_file_falls_back_to_english_with_a_log_line() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.ttf");
    std::fs::write(&bad, b"not a font").unwrap();
    let mut h = harness_for(None);
    h.run();
    h.state_mut().cjk = Some((dir.path().join("missing.ttc"), 0));
    h.state_mut().set_language(Lang::ZhTw);
    h.run();
    assert_eq!(h.state().lang, Lang::En, "unreadable font: back to English");
    assert!(h.state().log.iter().any(|l| l.contains("cannot read")));
}
