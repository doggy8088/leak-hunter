# leak-hunter

<p align="center">
  <img src="public/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**Languages:** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter` is a local-first defensive repository secret-scanning CLI. It ships as a single cross-platform binary that scans GitHub repository URLs, `owner/repo` shorthand, GitHub SSH targets, or local folders, then emits Text, JSON, or Markdown reports.

The Rust crate is the only core implementation. The npm package `leak-hunter` is a thin wrapper that installs and runs the native binary produced by cargo-dist in GitHub Releases.

## Install

```bash
cargo install --path .
```

Or install the npm package:

```bash
npm install -g leak-hunter
leak-hunter --help
```

## Quick start

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

Supported GitHub targets:

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## CLI options

| Option | Description |
|---|---|
| `--json` | Output machine-readable JSON; shortcut for JSON reports. |
| `--format <text\|json\|markdown>` | Choose the report format. |
| `--output <path>` | Write the report to a file and create parent directories when needed. |
| `--min-risk <0-100>` | Show only findings at or above the risk threshold. |
| `--include <glob>` / `--exclude <glob>` | Limit scan scope; can be repeated. |
| `--no-default-exclude` | Disable built-in exclusion rules. |
| `--max-file-size-mb <n>` | Set the per-file scan size limit. |
| `--concurrency <n>` | Set how many files are scanned in parallel. |
| `--no-redact` | Output raw secret values; use only for local manual review. |
| `--keep-temp` | Keep temporary clones for GitHub targets. |
| `--cache-dir <dir>` | Set the GitHub temporary clone directory; default is `.leak-hunter-cache`. |
| `--branch <name>` | Scan a specific branch or tag. |
| `--debug` | Print scan decisions, candidate scores, and min-risk filtering reasons to stderr. |
| `-v, --version` | Print version information. |

`--json` and an explicit `--format` are mutually exclusive so CI scripts do not produce ambiguous output.

## Reports

Text reports are designed for direct terminal review:

```bash
leak-hunter . --format text
```

The report starts with the Leak Hunter ASCII banner and includes the target, resolved scan root, scan time, scanned and skipped file counts, finding count, risk buckets, redaction status, and a finding table.

JSON reports are better for CI artifacts, `jq` processing, and system integrations:

```bash
leak-hunter . --json --output leak-hunter-report.json
```

Example query for high-risk findings:

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## Scan strategy

1. Resolve the local or GitHub target.
2. Clone GitHub repositories into `.leak-hunter-cache` or the directory specified by `--cache-dir`.
3. Walk files with gitignore-aware include / exclude glob handling.
4. Skip binary files or files above the configured size limit.
5. Apply the built-in pattern inventory and context-aware risk model.
6. Reduce common noise from npm integrity hashes in package-lock files, Firebase public API key context, and docs/example paths.
7. Redact by default, then sort output by risk score, path, and position.
8. Remove temporary GitHub clones unless `--keep-temp` is set.

## Detection highlights

The current rebuilt rules cover:

- OpenAI, Google API keys, GitHub tokens, Stripe, Slack, Sentry, and Docker Hub PATs
- AWS access key / secret key pairing
- Azure Storage connection strings, AccountKeys, and SAS URIs
- Popular framework app secrets such as Django, Flask, Rails, Laravel, NextAuth, Nuxt, Spring, and ASP.NET
- Database connection strings and URIs, including SQL Server-style connection strings, PostgreSQL, MongoDB, and Redis
- JWTs, PEM private keys, GCP service account JSON, and Google OAuth client secrets

## npm package and checksums

`npm/postinstall.cjs` maps the current platform to a cargo-dist target, downloads the release archive and matching `.sha256` file, verifies the SHA-256 checksum, then extracts and installs the native binary. npm publishing uses Trusted Publishing / OIDC instead of a long-lived `NPM_TOKEN`. Before publish, `prepublishOnly` runs npm tests, `npm pack --dry-run`, and verifies that every release archive and checksum exists.

## Development

```bash
cargo fmt --all -- --check
cargo test
cargo build --release
npm test
npm pack --dry-run
```

Self-scan:

```bash
cargo run --quiet -- --json --min-risk 40 . \
  | jq '{findings: .summary.findings, filesEnumerated: .summary.filesEnumerated}'
```

## Safety

Redaction is enabled by default. Do not publish unredacted reports. Test fixtures must use synthetic values assembled from string fragments so GitHub push protection is not triggered.
