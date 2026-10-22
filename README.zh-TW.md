# OmniDecomp

[English](README.md) | [繁體中文](README.zh-TW.md)

以 Rust 撰寫的可執行檔靜態分析工具組。它能讀取 PE、ELF、Mach-O 檔案,反組譯 x86 / x86-64 / AArch64 程式碼,還原函式、交互參照、控制流程圖與呼叫圖,並讀取 .NET 與 Java class 的中繼資料。命令列工具與桌面介面共用同一個分析核心。反編譯成 C# 或 Java 是交給外部引擎(ilspycmd、CFR)完成,這些引擎需要你自行安裝並啟用。

**只做靜態分析。** 你分析的檔案只會被讀取,絕不會被執行、載入或上傳。沒有任何網路連線,也沒有遙測。

狀態:規劃的五個階段(核心、引擎與報告、桌面介面、外掛與反編譯、安全加固與發布)都已實作,版本為 0.1.0,尚未選定授權。哪些功能已驗證、哪些沒有,列在 [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) 與 [docs/SUPPORTED_FORMATS.md](docs/SUPPORTED_FORMATS.md)(皆為英文);倚賴某項功能之前請先看過。

## 功能

| 範圍 | 說明 |
|---|---|
| 檔案格式 | PE32 / PE32+、ELF32 / ELF64、單一架構的 Mach-O(通用/fat 二進位會被拒絕)、.NET 組件(中繼資料)、Java `.class`(結構) |
| 反組譯 | x86 / x86-64 使用 iced-x86,AArch64 使用 yaxpeax-arm。線性掃描,Intel 語法 |
| 分析 | 符號(匯入、匯出、ELF symtab)、函式(進入點、符號、`.pdata`、`.eh_frame`、直接呼叫)、交互參照、控制流程圖、呼叫圖、字串、PE 偵錯資訊(PDB 參照) |
| 報告 | JSON、文字、CSV、HTML(CSV 儲存格與 HTML 都會做跳脫) |
| 反編譯 | .NET(ilspycmd)與 Java(CFR),只能透過已啟用的外掛;輸出視為不可信的文字 |
| 桌面介面 | 檔案資訊、函式/符號/字串清單、反組譯、十六進位檢視、搜尋、交互參照、控制流程圖與呼叫圖、外掛管理與反編譯面板、深色/淺色主題、字型設定,以及**英文與繁體中文** |

不支援的格式或架構會以明確的錯誤碼失敗,不會猜測結果。

## 安裝

預先打包的 zip 由 `scripts/package.py` 產生:

| 平台 | 狀態 |
|---|---|
| Windows 11 x86-64 | 已建置、測試並做過 smoke test |
| Linux x86-64(glibc 2.39 以上,例如 Ubuntu 24.04) | 已在 WSL2 建置、測試並做過 smoke test |
| macOS(Apple silicon、Intel) | **尚未驗證**:兩個目標都通過編譯檢查,但還沒有在 Mac 上實際執行或測試過 |

解壓縮後執行 `omnidecomp --version`。SHA-256 核對、升級、解除安裝與疑難排解請見 [docs/INSTALL.md](docs/INSTALL.md)(英文)。

從原始碼建置(`rust-toolchain.toml` 固定使用 Rust 1.99.0;所有相依套件都是純 Rust,不需要 C 工具鏈):

```
cargo build --release
cargo test
cargo clippy --all-targets
```

## 命令列

```
omnidecomp info <檔案> [--format json]
omnidecomp disasm <檔案> [--arch x86_64] [--section .text] [--max-instructions N] [--format json]
omnidecomp symbols <檔案>          omnidecomp functions <檔案>
omnidecomp xrefs <檔案> [--to 0x401000] [--from 0x401000]
omnidecomp cfg <檔案> --function 0x401000 [--format text|json|dot]
omnidecomp callgraph <檔案> [--format text|json|dot]
omnidecomp strings <檔案> [--min-length 4]
omnidecomp report <檔案> [--format json|text|csv|html] [--output report.json]
omnidecomp dotnet <組件.dll>       omnidecomp java <檔案.class>
omnidecomp engines list
omnidecomp plugins list | enable <id> | disable <id>
omnidecomp decompile <組件.dll|檔案.class> --engine ilspycmd --allow-external-exec [--output out.cs]
```

全域選項:`--max-file-size-mb`(預設 256)、`--timeout-secs`(預設 60)、`--plugins-dir`、`--state-file`。錯誤會以 `error[<代碼>]: 訊息` 的形式輸出到 stderr。

結束碼:0 成功、2 引數錯誤、3 I/O 錯誤、10 檔案被截斷、11 結構異常、12 不支援的格式、13 不支援的架構、14 超出限制、15 未知的引擎、16 輸出路徑無效、17 已取消、18 逾時、19 未知的外掛、20 外掛已停用、21 外掛不相容、22 外部引擎失敗。

命令列的訊息目前只有英文。

## 桌面介面

```
omnidecomp-gui [檔案]
```

可用「開啟檔案…」按鈕、直接輸入路徑,或把檔案拖到視窗上來開啟。在呼叫目標或圖形節點上連點兩下,或點一下交互參照,即可跳到該處。

**語言。** 開啟「View / 檢視」選單,選擇 **English** 或 **繁體中文**。選擇會存在外掛狀態檔旁邊的 `gui.json`;第一次啟動時會依系統語系(`LANG`、`LC_ALL`)決定。繁體中文需要一個能顯示中文字的字型:egui 內建字型沒有中文字,本專案也沒有附帶字型。程式會使用系統上已安裝的字型(Windows 用微軟正黑體、Linux 用 Noto Sans CJK、macOS 用蘋方;目前只試過 Windows 的字型),而且只有在選擇中文時才會載入;找不到字型時中文選項無法使用,選單會說明原因。也可以用環境變數 `OMNIDECOMP_CJK_FONT=<路徑>[,<字型索引>]` 指定字型。只有介面文字被翻譯,檔案內容、錯誤代碼、引擎與反編譯器的輸出維持原樣。

## 外掛與反編譯

外掛是一個含有 `plugin.json` 的資料夾,不會有任何東西被載入到程式中。外部反編譯器必須同時滿足下列條件才會啟動:外掛已啟用(會記錄其設定檔與程式的 SHA-256)、執行時再次通過檢查,而且你同意這一次執行(命令列用 `--allow-external-exec`,介面按「允許並執行」)。引擎以你的使用者權限執行,沒有沙箱。詳見 [docs/PLUGIN_API.md](docs/PLUGIN_API.md)(英文)。引擎本身不隨附:

```
dotnet tool install -g ilspycmd
omnidecomp plugins enable ilspycmd
omnidecomp decompile app.dll --engine ilspycmd --allow-external-exec
```

CFR 需要一個包住 jar 的小型 `cfr` 啟動器(見 `plugins/cfr/NOTICE.md`)。

## 安全性

所有輸入都視為有敵意:讀取皆做邊界檢查、運算做溢位檢查、有大小/數量/時間限制、可取消、驗證輸出路徑、顯示的名稱會移除控制字元,而且整個專案不使用 `unsafe`。突變測試(位元組翻轉、截斷)會把每種樣本送進整條分析流程;這是回歸測試,不是覆蓋率導向的 fuzzing。詳見 [docs/SECURITY.md](docs/SECURITY.md)(英文)。

## 專案結構

```
crates/core       資料模型、錯誤碼、限制、取消機制
crates/formats    PE / ELF / Mach-O / .NET / Java 解析器
crates/engines    反組譯引擎(iced-x86、yaxpeax-arm)
crates/app        命令列與介面共用的工作流程
crates/plugins    外掛設定檔、啟用狀態,也是唯一會啟動第三方程式的地方
crates/cli        命令列前端
crates/viewmodel  不依賴任何 UI 工具包的介面狀態
crates/gui        桌面前端(egui)
crates/testsamples  測試用的自建樣本檔與替身反編譯器
```

其他文件:[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)、[docs/ROADMAP.md](docs/ROADMAP.md)、[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 授權

尚未選定。所有編入程式的第三方授權列於 `THIRD_PARTY_NOTICES.md`;正式發布包中另附 `THIRD_PARTY_LICENSES.md` 與 SBOM(`omnidecomp.cdx.json`)。
