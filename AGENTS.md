# AGENTS.md

## 專案概覽

`leak-hunter` 是 Rust 實作的跨平台 repository secret scanner。Rust crate 是唯一的核心實作；npm package 只是 thin wrapper，用來透過 npm 安裝 native binary。

## 常用指令

- 格式檢查：`cargo fmt --all -- --check`
- 測試：`cargo test`
- Release build：`cargo build --release`
- npm package dry run：`npm pack --dry-run`

## 工作規範

- 不要提交 `target/`、`node_modules/`、`.leak-hunter-cache/` 或 npm postinstall 產生的 `npm/leak-hunter-bin/`。
- 修改 scanner 行為時，優先新增或更新 Rust 測試。
- 預設輸出必須維持 redaction；只有使用者明確指定 `--no-redact` 才能輸出原文。
- 測試 fixture 只能使用 synthetic / fake secret-like values，且應避免觸發 GitHub push protection。

## Git commit 規範

本專案的 commit message 採用 Conventional Commits 1.0.0（CC 1.0.0）。

- 格式：`<type>[optional scope][!]: <description>`。
- `type` 必須是小寫名詞；優先使用 `feat`、`fix`、`docs`、`test`、`refactor`、`build`、`ci`、`chore`。
- `feat` 表示新增功能，對應 SemVer minor；`fix` 表示修正 bug，對應 SemVer patch。
- `scope` 可選，使用小寫短名詞，例如 `docs`、`scanner`、`npm`、`ci`。
- `description` 必填，使用繁體中文（zh-tw）撰寫，不以句號結尾。
- 重大破壞性變更必須在 type/scope 後加 `!`，或在 footer 使用 `BREAKING CHANGE: <description>`；這類 commit 對應 SemVer major。
- Body 可選，需與 header 空一行，用來說明動機、背景與行為差異，不重述 diff。
- Footer 可選，需與 body 空一行；issue 連結使用 `Refs: #123` 或 `Closes: #123`。
- 多行 commit message 必須使用真實換行字元分隔 header、body 與 footer；不要把字面量 `\n` 寫進 commit message 或 git log。
- 每個 commit 聚焦單一邏輯變更；不要把不相關修改混在同一個 commit。
- Commit 前確認不要納入未請求或使用者既有的 unrelated changes。

範例：

```text
docs(readme): 新增本地化文件連結

feat(scanner)!: 變更預設風險閾值

BREAKING CHANGE: 當發現項目達到或高於閾值時，掃描現在會導致 CI 失敗
```
