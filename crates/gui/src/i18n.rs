//! Interface language. English texts in the source are the keys; `tr` looks the key up in the Traditional
//! Chinese table and falls back to the English text, so an untranslated string shows in English rather than
//! as an empty label. Only the interface chrome is translated. Names, addresses, mnemonics, error codes
//! and messages that come from the analysis layers or from files are shown as they are.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    En,
    ZhTw,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::ZhTw => "zh-TW",
        }
    }

    /// Name of the language in that language, for the language chooser.
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::ZhTw => "繁體中文",
        }
    }

    pub fn from_code(s: &str) -> Option<Lang> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "en" | "en-us" | "en-gb" => Some(Lang::En),
            "zh-tw" | "zh-hant" | "zh-hk" | "zh-mo" => Some(Lang::ZhTw),
            _ => None,
        }
    }

    /// Guess from the usual locale variables (`LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, `LANG`). Used only when the
    /// user has not chosen a language yet. Windows has no such variables, so it starts in English.
    pub fn from_env() -> Lang {
        for var in ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"] {
            if let Some(v) = std::env::var_os(var) {
                let v = v.to_string_lossy().to_string();
                let tag = v.split([':', '.', '@']).next().unwrap_or("");
                if let Some(l) = Lang::from_code(tag) {
                    return l;
                }
                if !tag.is_empty() && tag != "C" && tag != "POSIX" {
                    return Lang::En;
                }
            }
        }
        Lang::En
    }
}

/// Translates `en`; returns it unchanged for English or when there is no entry.
pub fn tr(lang: Lang, en: &str) -> &str {
    match lang {
        Lang::En => en,
        Lang::ZhTw => table().get(en).copied().unwrap_or(en),
    }
}

/// Translates a template and fills its `{}` placeholders in order.
pub fn trf(lang: Lang, en: &str, args: &[&str]) -> String {
    let t = tr(lang, en);
    let mut out = String::with_capacity(t.len() + 16);
    let mut it = args.iter();
    let mut rest = t;
    while let Some(i) = rest.find("{}") {
        out.push_str(&rest[..i]);
        out.push_str(it.next().copied().unwrap_or(""));
        rest = &rest[i + 2..];
    }
    out.push_str(rest);
    out
}

fn table() -> &'static HashMap<&'static str, &'static str> {
    static T: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    T.get_or_init(|| ZH_TW.iter().copied().collect())
}

// ---------------------------------------------------------------------------------------------
// Saved choice

/// The language choice lives in a small file beside the plugin state file, so it follows the same
/// per-user location and the same `--state-file` / environment overrides.
pub fn prefs_path(state_file: Option<&Path>) -> Option<PathBuf> {
    state_file.and_then(|s| s.parent()).map(|d| d.join("gui.json"))
}

pub fn load_pref(path: Option<&Path>) -> Option<Lang> {
    let bytes = std::fs::read(path?).ok().filter(|b| b.len() < 4096)?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Lang::from_code(v.get("language")?.as_str()?)
}

/// Best effort: a failure to save only means the choice is not remembered.
pub fn save_pref(path: Option<&Path>, lang: Lang) -> Result<(), String> {
    let path = path.ok_or_else(|| "no per-user config folder".to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, format!("{{\"language\":\"{}\"}}\n", lang.code())).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------------------------
// Traditional Chinese (Taiwan) table. Keys are the exact English texts used in the source.

pub(crate) const ZH_TW: &[(&str, &str)] = &[
    // window, file bar
    ("static analysis only: files are never executed", "僅做靜態分析:絕不會執行檔案"),
    ("opening {}", "正在開啟 {}"),
    ("loaded {} ({} instructions)", "已載入 {}({} 條指令)"),
    ("File:", "檔案:"),
    ("path, use Open file..., or drop a file here", "輸入路徑、按「開啟檔案…」,或把檔案拖到這裡"),
    ("Open file...", "開啟檔案…"),
    ("Open", "開啟"),
    ("Cancel", "取消"),
    ("engine working: {}", "引擎處理中:{}"),
    ("starting", "啟動中"),
    ("reading and parsing", "讀取並解析"),
    ("disassembling", "反組譯中"),
    ("symbols", "符號"),
    ("recovering functions", "還原函式"),
    ("strings", "字串"),
    // View menu
    ("View", "檢視"),
    ("Dark", "深色"),
    ("Light", "淺色"),
    ("font size", "字型大小"),
    ("line spacing", "行距"),
    ("padded addresses", "補零位址"),
    ("short", "簡短"),
    ("color mnemonics", "助記符上色"),
    ("Language", "語言"),
    ("A Chinese font was not found on this system, so Traditional Chinese is unavailable.", "此系統找不到中文字型,因此無法使用繁體中文。"),
    ("Could not save the language choice: {}", "無法儲存語言選擇:{}"),
    // left panel
    ("Info", "資訊"),
    ("Functions", "函式"),
    ("Symbols", "符號"),
    ("Strings", "字串"),
    ("No file loaded. Enter a path or drop a PE / ELF / Mach-O file on this window.", "尚未載入檔案。請輸入路徑,或把 PE / ELF / Mach-O 檔案拖到此視窗。"),
    ("name", "名稱"),
    ("format", "格式"),
    ("architecture", "架構"),
    ("entry point", "進入點"),
    ("none", "無"),
    ("size", "大小"),
    ("{} bytes", "{} 位元組"),
    ("sha-256", "SHA-256"),
    ("pdb", "PDB"),
    ("{} (guid {}, age {})", "{}(GUID {},age {})"),
    (".net", ".NET"),
    ("{} types, {} methods ({} metadata only; see the Decompile tab)", "{} 個型別、{} 個方法({} 僅有中繼資料;請見「反編譯」分頁)"),
    ("Sections", "區段"),
    ("va", "VA"),
    ("[exec]", "[可執行]"),
    ("filter by name or address", "依名稱或位址篩選"),
    ("filter by name", "依名稱篩選"),
    ("filter text", "篩選文字"),
    ("Functions unavailable for this file (see Log).", "此檔案無法取得函式(請見記錄)。"),
    ("(import)", "(匯入)"),
    // center tabs
    ("Disassembly", "反組譯"),
    ("CFG", "控制流程圖"),
    ("Call graph", "呼叫圖"),
    ("Decompile", "反編譯"),
    ("Plugins", "外掛"),
    ("call graph unavailable for this file", "此檔案無法取得呼叫圖"),
    ("No functions were recovered for this file, so there is no graph. See the Log tab.", "此檔案沒有還原出任何函式,因此沒有圖形。請見「記錄」分頁。"),
    ("Graphs appear here once a file is loaded.", "載入檔案後,圖形會顯示在這裡。"),
    ("depth", "深度"),
    ("CFG: blocks of {} - {} nodes, {} edges{}", "控制流程圖:{} 的基本區塊 - {} 個節點、{} 條邊{}"),
    ("Calls: functions around {} - {} nodes, {} edges{}", "呼叫圖:{} 周邊的函式 - {} 個節點、{} 條邊{}"),
    (" (cut by a limit)", "(因上限而截斷)"),
    ("{}\n(leaves graph)", "{}\n(離開此圖)"),
    ("Derived from linear-sweep disassembly. Indirect jumps and calls are not resolved. Click a node to select it; double-click to show it in the disassembly.", "由線性掃描反組譯推得。間接跳躍與間接呼叫不會被解析。點一下節點可選取;連點兩下會在反組譯中顯示。"),
    ("Disassembly (not decompilation) appears here once a file is loaded.", "載入檔案後,反組譯(不是反編譯)會顯示在這裡。"),
    ("Disassembly unavailable for this file; see the Log tab. No output is guessed.", "此檔案無法反組譯;請見「記錄」分頁。不會猜測輸出。"),
    ("{} {} - {} - {} instructions{}", "{} {} - {} - {} 條指令{}"),
    (" (truncated by limit)", "(因上限而截斷)"),
    ("Hex (synced to selection)", "十六進位(與選取同步)"),
    // bottom panel
    ("Search", "搜尋"),
    ("Cross-references", "交互參照"),
    ("Log", "記錄"),
    ("name, text, mnemonic, or hex address", "名稱、文字、助記符,或十六進位位址"),
    ("all", "全部"),
    ("functions", "函式"),
    ("instructions", "指令"),
    ("{} result(s){}", "{} 筆結果{}"),
    (" (limit reached)", "(已達上限)"),
    ("Select an instruction or function to see references to and from it.", "選取一條指令或一個函式,即可查看指向它與由它發出的參照。"),
    ("references to {}", "指向 {} 的參照"),
    ("references from {}", "從 {} 發出的參照"),
    ("{} {} -> here  ({} confidence)", "{} {} -> 此處  (可信度 {})"),
    ("here {} -> {}  ({} confidence)", "此處 {} -> {}  (可信度 {})"),
    ("Clear log", "清除記錄"),
    // plugins tab
    ("Refresh", "重新整理"),
    ("plugins folder: {}", "外掛資料夾:{}"),
    ("Plugins are declarative manifests; nothing is loaded into this program. An external decompiler is started only after you enable it here and confirm a run on the Decompile tab.", "外掛只是宣告式的設定檔,不會載入到本程式中。外部反編譯器只有在你於此啟用、並在「反編譯」分頁確認該次執行後才會啟動。"),
    ("No per-user config folder was found, so changes cannot be saved. Start with --state-file via the command line tool, or set OMNIDECOMP_STATE_FILE.", "找不到使用者設定資料夾,因此無法儲存變更。請設定環境變數 OMNIDECOMP_STATE_FILE。"),
    ("Enable {}", "啟用 {}"),
    ("Disable {}", "停用 {}"),
    ("license", "授權"),
    ("source", "來源"),
    ("handles", "處理"),
    ("plugin {} enabled", "已啟用外掛 {}"),
    ("plugin {} disabled", "已停用外掛 {}"),
    ("Trust this plugin?", "信任這個外掛?"),
    ("license: {}   source: {}", "授權:{}   來源:{}"),
    ("(none)", "(無)"),
    ("Enabling records a fingerprint (SHA-256) of the plugin manifest and of the program it runs. If either changes, the plugin stops working until you enable it again.", "啟用時會記錄外掛設定檔與其執行程式的指紋(SHA-256)。其中任一個被更動,外掛就會停止運作,直到你重新啟用。"),
    ("When you decompile, that program runs with your user rights. There is no sandbox. Enable it only if you trust it.", "反編譯時,該程式會以你的使用者權限執行,沒有沙箱。請只啟用你信任的外掛。"),
    ("Trust and enable {}", "信任並啟用 {}"),
    // decompile tab
    ("Start an external program?", "要啟動外部程式嗎?"),
    ("program: {}", "程式:{}"),
    ("arguments: {}", "引數:{}"),
    ("The file is only passed to it as a path. OmniDecomp does not execute the file, but this decompiler runs with your user rights and may read it fully. This permission is for this run only.", "檔案只會以路徑傳給它。OmniDecomp 不會執行該檔案,但這個反編譯器會以你的使用者權限執行,並可能完整讀取檔案。這項許可只對這一次執行有效。"),
    ("Allow and run", "允許並執行"),
    ("Cancel run", "取消執行"),
    ("starting {} on {}", "正在以 {} 處理 {}"),
    ("decompile cancelled before starting", "反編譯在啟動前已取消"),
    ("decompiled {} with {} {}", "已反編譯 {}(使用 {} {})"),
    ("Decompile with an external engine", "使用外部引擎反編譯"),
    ("Works on .NET assemblies and Java .class files (the path in the File box). Native code has no decompiler here.", "適用於 .NET 組件與 Java .class 檔(使用檔案欄中的路徑)。原生程式碼在這裡沒有反編譯器。"),
    ("No decompiler is enabled. Open the Plugins tab and enable one (for .NET: install ilspycmd, then Enable ilspycmd).", "尚未啟用任何反編譯器。請到「外掛」分頁啟用一個(.NET:先安裝 ilspycmd,再啟用 ilspycmd)。"),
    ("file:", "檔案:"),
    ("(enter a path above)", "(請在上方輸入路徑)"),
    ("Decompile this file", "反編譯這個檔案"),
    ("checking plugin and file...", "正在檢查外掛與檔案…"),
    ("Cancel decompile", "取消反編譯"),
    ("decompiling {}...", "正在反編譯 {}…"),
    ("Copy all", "全部複製"),
    ("{} lines", "{} 行"),
    ("output was produced by an external decompiler and is untrusted text", "輸出由外部反編譯器產生,屬於不可信的文字"),
    ("the analysed file itself was not executed", "被分析的檔案本身沒有被執行"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholders(s: &str) -> usize {
        s.matches("{}").count()
    }

    #[test]
    fn language_codes_and_environment() {
        assert_eq!(Lang::from_code("zh_TW"), Some(Lang::ZhTw));
        assert_eq!(Lang::from_code(" zh-Hant "), Some(Lang::ZhTw));
        assert_eq!(Lang::from_code("EN-us"), Some(Lang::En));
        assert_eq!(Lang::from_code("fr"), None);
        for l in [Lang::En, Lang::ZhTw] {
            assert_eq!(Lang::from_code(l.code()), Some(l));
        }
    }

    #[test]
    fn lookup_falls_back_to_english_and_fills_placeholders() {
        assert_eq!(tr(Lang::En, "Cancel"), "Cancel");
        assert_eq!(tr(Lang::ZhTw, "Cancel"), "取消");
        assert_eq!(tr(Lang::ZhTw, "never translated"), "never translated");
        assert_eq!(trf(Lang::En, "opening {}", &["a.exe"]), "opening a.exe");
        assert_eq!(trf(Lang::ZhTw, "opening {}", &["a.exe"]), "正在開啟 a.exe");
        // Too few arguments leave the hole empty instead of panicking; extras are ignored.
        assert_eq!(trf(Lang::En, "{} / {}", &["x"]), "x / ");
        assert_eq!(trf(Lang::En, "{}", &["x", "y"]), "x");
    }

    #[test]
    fn every_translation_keeps_its_placeholders_and_has_no_duplicate_key() {
        let mut seen = std::collections::HashSet::new();
        for (en, zh) in ZH_TW {
            assert!(seen.insert(*en), "duplicate key {en:?}");
            assert_eq!(placeholders(en), placeholders(zh), "placeholder count differs for {en:?}");
            assert!(!zh.trim().is_empty());
        }
    }

    fn unescape(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.next() {
                    Some('n') => out.push('\n'),
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(o) => out.push(o),
                    None => {}
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Texts passed to `tr(`/`trf(` in the GUI sources.
    fn used_keys() -> Vec<String> {
        let mut keys = Vec::new();
        // Every source file of the crate except this table and the tests, found on disk so a new panel is covered.
        fn sources(dir: &std::path::Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    sources(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") && !matches!(p.file_name().and_then(|n| n.to_str()), Some("i18n.rs" | "tests.rs")) {
                    out.push(std::fs::read_to_string(&p).unwrap());
                }
            }
        }
        let mut all = Vec::new();
        sources(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut all);
        for src in all.iter().map(String::as_str) {
            for marker in ["tr(lang, \"", "trf(lang, \""] {
                let mut rest = src;
                while let Some(i) = rest.find(marker) {
                    rest = &rest[i + marker.len()..];
                    let mut end = 0;
                    let b = rest.as_bytes();
                    while end < b.len() && b[end] != b'"' {
                        end += if b[end] == b'\\' { 2 } else { 1 };
                    }
                    keys.push(unescape(&rest[..end]));
                }
            }
        }
        keys
    }

    #[test]
    fn every_text_used_in_the_gui_has_a_translation_and_no_entry_is_unused() {
        let used = used_keys();
        assert!(used.len() > 80, "scanner found only {} keys", used.len());
        for k in &used {
            assert!(table().contains_key(k.as_str()), "no Traditional Chinese text for {k:?}");
        }
        let used: std::collections::HashSet<_> = used.into_iter().collect();
        for (en, _) in ZH_TW {
            // Entries listed for runtime lookups (picker title, scope names, status words) are exempt.
            let dynamic = ["starting", "reading and parsing", "disassembling", "recovering functions", "output was produced by an external decompiler and is untrusted text", "the analysed file itself was not executed"];
            assert!(used.contains(*en) || dynamic.contains(en), "unused translation {en:?}");
        }
    }

    #[test]
    fn preference_round_trip_and_bad_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("cfg").join("plugins.json");
        let p = prefs_path(Some(&state));
        assert_eq!(load_pref(p.as_deref()), None, "missing file");
        save_pref(p.as_deref(), Lang::ZhTw).unwrap();
        assert_eq!(load_pref(p.as_deref()), Some(Lang::ZhTw));
        save_pref(p.as_deref(), Lang::En).unwrap();
        assert_eq!(load_pref(p.as_deref()), Some(Lang::En));
        std::fs::write(p.as_ref().unwrap(), "{{{").unwrap();
        assert_eq!(load_pref(p.as_deref()), None, "corrupt file");
        std::fs::write(p.as_ref().unwrap(), r#"{"language":"klingon"}"#).unwrap();
        assert_eq!(load_pref(p.as_deref()), None, "unknown language");
        std::fs::write(p.as_ref().unwrap(), vec![b' '; 10_000]).unwrap();
        assert_eq!(load_pref(p.as_deref()), None, "oversized file");
        assert!(save_pref(None, Lang::En).is_err());
    }
}
