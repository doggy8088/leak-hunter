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
