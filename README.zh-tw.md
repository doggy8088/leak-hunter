# leak-hunter

<p align="center">
  <img src="public/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**語言：** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter` 是一套以本機執行為優先的防禦型 Repo 敏感資訊掃描 CLI。它提供單一跨平台 binary，可掃描 GitHub repository URL、`owner/repo` 簡寫、GitHub SSH target，或本機資料夾，並輸出 Text、JSON、Markdown 報告。

Rust crate 是唯一的核心實作；npm package `leak-hunter` 是 thin wrapper，用來安裝並執行 GitHub Release 內由 cargo-dist 產生的 native binary。

## 安裝

```bash
cargo install --path .
```

或使用 npm package：

```bash
npm install -g leak-hunter
leak-hunter --help
```

## 快速開始

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

支援的 GitHub target：

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## CLI 選項

| 選項 | 說明 |
|---|---|
| `--json` | 輸出 machine-readable JSON，等同 JSON report shortcut。 |
| `--format <text\|json\|markdown>` | 選擇報告格式。 |
| `--output <path>` | 將報告寫入檔案；必要時自動建立父目錄。 |
| `--min-risk <0-100>` | 只顯示達到風險門檻的 findings。 |
| `--include <glob>` / `--exclude <glob>` | 限制掃描範圍，可重複指定。 |
| `--no-default-exclude` | 關閉內建排除規則。 |
| `--max-file-size-mb <n>` | 單檔掃描大小上限。 |
| `--concurrency <n>` | 並行掃描檔案數。 |
| `--no-redact` | 輸出原文 secret；僅限本機人工複核。 |
| `--keep-temp` | 保留 GitHub target 的暫存 clone。 |
| `--cache-dir <dir>` | 指定 GitHub 暫存 clone 目錄，預設 `.leak-hunter-cache`。 |
| `--branch <name>` | 掃描指定 branch 或 tag。 |
| `--debug` | 將掃描決策、候選 finding 分數與 min-risk 篩選原因輸出到 stderr。 |
| `-v, --version` | 顯示版本資訊。 |

`--json` 與明確指定的 `--format` 互斥，以避免 CI 腳本產生模稜兩可的輸出。

## 報告

Text report 適合直接在終端機閱讀：

```bash
leak-hunter . --format text
```

內容會以 Leak Hunter ASCII banner 開場，並包含 target、實際掃描 root、掃描時間、掃描與略過檔案數、finding 數、風險 bucket、redaction 狀態與 finding 表格。

JSON report 適合 CI 保存、後續 `jq` 處理或匯入其他系統：

```bash
leak-hunter . --json --output leak-hunter-report.json
```

範例查詢高風險 finding：

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## 掃描策略

1. 解析本機或 GitHub target。
2. GitHub repository 會 clone 到 `.leak-hunter-cache` 或 `--cache-dir` 指定目錄。
3. 使用 gitignore-aware walker、`.leakhunterignore` 與 include / exclude glob；`.leakhunterignore` 使用 `.gitignore` 語法。
4. 略過 binary 或超過大小上限的檔案。
5. 套用內建 pattern inventory 與 context-aware risk model。
6. 對 package-lock npm integrity hashes、Firebase public API key context、docs/example 等常見 noise 降噪。
7. 預設 redaction，依風險分數、路徑與位置排序輸出。
8. 清除 GitHub 暫存 clone，除非使用 `--keep-temp`。

## 偵測重點

目前重建的 rules 包含：

- OpenAI、Google API Key、GitHub Token、Stripe、Slack、Sentry、Docker Hub PAT
- AWS access key / secret key pairing
- Azure Storage connection string / AccountKey / SAS URI
- Popular framework app secrets，例如 Django、Flask、Rails、Laravel、NextAuth、Nuxt、Spring、ASP.NET 等
- Database connection strings and URIs，例如 SQL Server-style connection string、PostgreSQL、MongoDB、Redis
- JWT、PEM private key、GCP service account JSON、Google OAuth client secret

## npm package 與 checksum

`npm/postinstall.cjs` 會依平台對應 cargo-dist target，下載 release archive 與對應 `.sha256`，驗證 SHA-256 後才解壓縮並安裝 native binary。npm 發佈使用 Trusted Publishing / OIDC，不使用長期 `NPM_TOKEN`。發布前的 `prepublishOnly` 會先跑 npm 測試、`npm pack --dry-run`，並確認所有 release archive 與 checksum 都已存在。

## 開發

```bash
cargo fmt --all -- --check
cargo test
cargo build --release
npm test
npm pack --dry-run
```

Self-scan：

```bash
cargo run --quiet -- --json --min-risk 40 . \
  | jq '{findings: .summary.findings, filesEnumerated: .summary.filesEnumerated}'
```

## 安全

Redaction 預設啟用。不要發佈未遮罩的報告。測試 fixture 必須使用 synthetic values，並用字串片段組合，避免觸發 GitHub push protection。
