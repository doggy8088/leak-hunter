# leak-hunter

<p align="center">
  <img src="public/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**言語:** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter` はローカル実行を優先する、防御目的のリポジトリ秘密情報スキャン CLI です。単一のクロスプラットフォーム binary で、GitHub repository URL、`owner/repo` 形式の省略表記、GitHub SSH target、またはローカルフォルダーをスキャンし、Text、JSON、Markdown レポートを出力できます。

Rust crate が唯一のコア実装です。npm package `leak-hunter` は、GitHub Releases に cargo-dist で生成された native binary をインストールして実行する thin wrapper です。

## インストール

```bash
cargo install --path .
```

npm package からもインストールできます。

```bash
npm install -g leak-hunter
leak-hunter --help
```

## クイックスタート

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

対応する GitHub target:

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## CLI オプション

| オプション | 説明 |
|---|---|
| `--json` | machine-readable JSON を出力します。JSON report のショートカットです。 |
| `--format <text\|json\|markdown>` | レポート形式を選択します。 |
| `--output <path>` | レポートをファイルに書き込み、必要に応じて親ディレクトリを作成します。 |
| `--min-risk <0-100>` | 指定したリスクしきい値以上の findings だけを表示します。 |
| `--include <glob>` / `--exclude <glob>` | スキャン範囲を制限します。複数回指定できます。 |
| `--no-default-exclude` | 組み込みの除外ルールを無効化します。 |
| `--max-file-size-mb <n>` | 1 ファイルあたりのスキャンサイズ上限を設定します。 |
| `--concurrency <n>` | 並列にスキャンするファイル数を設定します。 |
| `--no-redact` | secret の生値を出力します。ローカルでの手動レビューにのみ使用してください。 |
| `--keep-temp` | GitHub target の一時 clone を保持します。 |
| `--cache-dir <dir>` | GitHub の一時 clone ディレクトリを指定します。既定は `.leak-hunter-cache` です。 |
| `--branch <name>` | 指定した branch または tag をスキャンします。 |
| `--debug` | スキャン判断、候補 finding のスコア、min-risk フィルター理由を stderr に出力します。 |
| `-v, --version` | バージョン情報を表示します。 |

`--json` と明示的な `--format` は同時に指定できません。CI スクリプトの出力があいまいになることを防ぎます。

## レポート

Text report はターミナルで直接確認する用途に向いています。

```bash
leak-hunter . --format text
```

レポートは Leak Hunter ASCII banner から始まり、target、解決された scan root、スキャン時刻、スキャン済みおよびスキップされたファイル数、finding 数、リスク bucket、redaction 状態、finding table を含みます。

JSON report は CI artifact、`jq` 処理、他システムへの取り込みに向いています。

```bash
leak-hunter . --json --output leak-hunter-report.json
```

高リスク finding を抽出する例:

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## スキャン戦略

1. ローカルまたは GitHub target を解決します。
2. GitHub repository は `.leak-hunter-cache` または `--cache-dir` で指定したディレクトリに clone します。
3. gitignore-aware walker と include / exclude glob を使用します。
4. binary ファイルまたはサイズ上限を超えるファイルをスキップします。
5. 組み込みの pattern inventory と context-aware risk model を適用します。
6. package-lock の npm integrity hashes、Firebase public API key context、docs/example パスなどの一般的な noise を低減します。
7. 既定で redaction し、リスクスコア、パス、位置で並べ替えて出力します。
8. `--keep-temp` が指定されていない限り、GitHub の一時 clone を削除します。

## 検出ハイライト

現在再構築された rules は次を対象にしています。

- OpenAI、Google API Key、GitHub Token、Stripe、Slack、Sentry、Docker Hub PAT
- AWS access key / secret key pairing
- Azure Storage connection string / AccountKey / SAS URI
- Django、Flask、Rails、Laravel、NextAuth、Nuxt、Spring、ASP.NET などの popular framework app secrets
- SQL Server-style connection string、PostgreSQL、MongoDB、Redis などの database connection strings and URIs
- JWT、PEM private key、GCP service account JSON、Google OAuth client secret

## npm package と checksum

`npm/postinstall.cjs` は現在のプラットフォームを cargo-dist target に対応付け、release archive と対応する `.sha256` をダウンロードし、SHA-256 checksum を検証してから native binary を展開してインストールします。npm publish は長期 `NPM_TOKEN` ではなく Trusted Publishing / OIDC を使用します。公開前の `prepublishOnly` は npm tests、`npm pack --dry-run` を実行し、すべての release archive と checksum が存在することを確認します。

## 開発

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

## 安全性

Redaction は既定で有効です。redact されていないレポートを公開しないでください。テスト fixture には synthetic values を使用し、GitHub push protection を発火させないよう文字列片から組み立ててください。
