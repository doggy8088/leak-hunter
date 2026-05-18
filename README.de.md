# leak-hunter

<p align="center">
  <img src="docs/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**Sprachen:** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter` ist ein lokal ausgerichtetes, defensives CLI zum Scannen von Repository-Secrets. Es liefert ein einzelnes plattformübergreifendes binary, das GitHub repository URLs, `owner/repo`-Kurzformen, GitHub SSH targets oder lokale Ordner scannt und Berichte als Text, JSON oder Markdown ausgibt.

Die Rust crate ist die einzige Kernimplementierung. Das npm package `leak-hunter` ist ein thin wrapper, der das von cargo-dist in GitHub Releases erzeugte native binary installiert und ausführt.

## Installation

```bash
cargo install --path .
```

Oder über das npm package:

```bash
npm install -g leak-hunter
leak-hunter --help
```

## Schnellstart

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

Unterstützte GitHub targets:

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## CLI-Optionen

| Option | Beschreibung |
|---|---|
| `--json` | Gibt machine-readable JSON aus; Kurzform für JSON reports. |
| `--format <text\|json\|markdown>` | Wählt das Berichtsformat. |
| `--output <path>` | Schreibt den Bericht in eine Datei und legt bei Bedarf Parent-Verzeichnisse an. |
| `--min-risk <0-100>` | Zeigt nur findings ab dem Risikoschwellenwert. |
| `--include <glob>` / `--exclude <glob>` | Begrenzt den Scanbereich; mehrfach verwendbar. |
| `--no-default-exclude` | Deaktiviert integrierte Ausschlussregeln. |
| `--max-file-size-mb <n>` | Setzt die Scan-Größenobergrenze pro Datei. |
| `--concurrency <n>` | Setzt die Anzahl parallel gescannter Dateien. |
| `--no-redact` | Gibt rohe secret-Werte aus; nur für lokale manuelle Prüfung verwenden. |
| `--keep-temp` | Behält temporary clones für GitHub targets. |
| `--cache-dir <dir>` | Setzt das GitHub temporary clone-Verzeichnis; Standard ist `.leak-hunter-cache`. |
| `--branch <name>` | Scannt eine bestimmte branch oder ein tag. |
| `--debug` | Gibt Scan-Entscheidungen, candidate finding-Scores und min-risk-Filtergründe auf stderr aus. |
| `-v, --version` | Zeigt Versionsinformationen. |

`--json` und ein explizites `--format` schließen sich gegenseitig aus, damit CI-Skripte keine mehrdeutige Ausgabe erzeugen.

## Berichte

Text reports sind für die direkte Prüfung im Terminal gedacht:

```bash
leak-hunter . --format text
```

Der Bericht beginnt mit dem Leak Hunter ASCII banner und enthält target, aufgelösten scan root, Scanzeit, Anzahl gescannter und übersprungener Dateien, Anzahl findings, risk buckets, redaction-Status und eine finding-Tabelle.

JSON reports eignen sich für CI-Artefakte, `jq`-Verarbeitung und Integrationen:

```bash
leak-hunter . --json --output leak-hunter-report.json
```

Beispielabfrage für findings mit hohem Risiko:

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## Scan-Strategie

1. Lokales oder GitHub target auflösen.
2. GitHub repositories nach `.leak-hunter-cache` oder in das mit `--cache-dir` angegebene Verzeichnis clonen.
3. Dateien mit gitignore-aware walker und include / exclude globs durchlaufen.
4. Binary files oder Dateien oberhalb der Größenbegrenzung überspringen.
5. Integriertes pattern inventory und context-aware risk model anwenden.
6. Häufiges noise aus npm integrity hashes in package-lock, Firebase public API key context und docs/example-Pfaden reduzieren.
7. Standardmäßig redaction anwenden und Ausgabe nach risk score, path und position sortieren.
8. Temporary GitHub clones entfernen, außer `--keep-temp` ist gesetzt.

## Erkennungs-Highlights

Die aktuell neu aufgebauten rules decken ab:

- OpenAI, Google API Key, GitHub Token, Stripe, Slack, Sentry und Docker Hub PAT
- AWS access key / secret key pairing
- Azure Storage connection string / AccountKey / SAS URI
- Popular framework app secrets wie Django, Flask, Rails, Laravel, NextAuth, Nuxt, Spring und ASP.NET
- Database connection strings and URIs wie SQL Server-style connection string, PostgreSQL, MongoDB und Redis
- JWT, PEM private key, GCP service account JSON und Google OAuth client secret

## npm package und checksum

`npm/postinstall.cjs` ordnet die aktuelle Plattform einem cargo-dist target zu, lädt die release archive und die passende `.sha256`-Datei herunter, verifiziert den SHA-256 checksum und entpackt sowie installiert danach das native binary. npm Publishing nutzt Trusted Publishing / OIDC statt eines langfristigen `NPM_TOKEN`. Vor dem Publish führt `prepublishOnly` npm tests und `npm pack --dry-run` aus und prüft, dass jede release archive und jeder checksum vorhanden ist.

## Entwicklung

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

## Sicherheit

Redaction ist standardmäßig aktiviert. Veröffentlichen Sie keine unredacted Berichte. Test fixtures müssen synthetic values verwenden, die aus Stringfragmenten zusammengesetzt werden, damit GitHub push protection nicht ausgelöst wird.
