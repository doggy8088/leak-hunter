# leak-hunter

<p align="center">
  <img src="docs/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**语言：** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter` 是一个本地优先的防御型仓库敏感信息扫描 CLI。它提供单一跨平台 binary，可扫描 GitHub repository URL、`owner/repo` 简写、GitHub SSH target，或本地文件夹，并输出 Text、JSON、Markdown 报告。

Rust crate 是唯一的核心实现；npm package `leak-hunter` 是 thin wrapper，用来安装并运行 GitHub Release 中由 cargo-dist 生成的 native binary。

## 安装

```bash
cargo install --path .
```

或使用 npm package：

```bash
npm install -g leak-hunter
leak-hunter --help
```

## 快速开始

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

支持的 GitHub target：

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## CLI 选项

| 选项 | 说明 |
|---|---|
| `--json` | 输出 machine-readable JSON，等同 JSON report shortcut。 |
| `--format <text\|json\|markdown>` | 选择报告格式。 |
| `--output <path>` | 将报告写入文件；必要时自动创建父目录。 |
| `--min-risk <0-100>` | 只显示达到风险门槛的 findings。 |
| `--include <glob>` / `--exclude <glob>` | 限制扫描范围，可重复指定。 |
| `--no-default-exclude` | 关闭内置排除规则。 |
| `--max-file-size-mb <n>` | 单文件扫描大小上限。 |
| `--concurrency <n>` | 并行扫描文件数。 |
| `--no-redact` | 输出原文 secret；仅限本地人工复核。 |
| `--keep-temp` | 保留 GitHub target 的临时 clone。 |
| `--cache-dir <dir>` | 指定 GitHub 临时 clone 目录，默认 `.leak-hunter-cache`。 |
| `--branch <name>` | 扫描指定 branch 或 tag。 |
| `--debug` | 将扫描决策、候选 finding 分数与 min-risk 过滤原因输出到 stderr。 |
| `-v, --version` | 显示版本信息。 |

`--json` 与明确指定的 `--format` 互斥，以避免 CI 脚本产生含糊输出。

## 报告

Text report 适合直接在终端阅读：

```bash
leak-hunter . --format text
```

内容会以 Leak Hunter ASCII banner 开场，并包含 target、实际扫描 root、扫描时间、扫描与跳过文件数、finding 数、风险 bucket、redaction 状态与 finding 表格。

JSON report 适合 CI 保存、后续 `jq` 处理或导入其他系统：

```bash
leak-hunter . --json --output leak-hunter-report.json
```

查询高风险 finding 的示例：

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## 扫描策略

1. 解析本地或 GitHub target。
2. GitHub repository 会 clone 到 `.leak-hunter-cache` 或 `--cache-dir` 指定目录。
3. 使用 gitignore-aware walker 与 include / exclude glob。
4. 跳过 binary 或超过大小上限的文件。
5. 套用内置 pattern inventory 与 context-aware risk model。
6. 对 package-lock npm integrity hashes、Firebase public API key context、docs/example 等常见 noise 降噪。
7. 默认 redaction，并按风险分数、路径与位置排序输出。
8. 清理 GitHub 临时 clone，除非使用 `--keep-temp`。

## 检测重点

当前重建的 rules 包含：

- OpenAI、Google API Key、GitHub Token、Stripe、Slack、Sentry、Docker Hub PAT
- AWS access key / secret key pairing
- Azure Storage connection string / AccountKey / SAS URI
- Popular framework app secrets，例如 Django、Flask、Rails、Laravel、NextAuth、Nuxt、Spring、ASP.NET 等
- Database connection strings and URIs，例如 SQL Server-style connection string、PostgreSQL、MongoDB、Redis
- JWT、PEM private key、GCP service account JSON、Google OAuth client secret

## npm package 与 checksum

`npm/postinstall.cjs` 会按平台映射 cargo-dist target，下载 release archive 与对应 `.sha256`，验证 SHA-256 后才解压并安装 native binary。npm 发布使用 Trusted Publishing / OIDC，不使用长期 `NPM_TOKEN`。发布前的 `prepublishOnly` 会先运行 npm 测试、`npm pack --dry-run`，并确认所有 release archive 与 checksum 都已存在。

## 开发

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

Redaction 默认启用。不要发布未遮罩的报告。测试 fixture 必须使用 synthetic values，并以字符串片段组合，避免触发 GitHub push protection。
