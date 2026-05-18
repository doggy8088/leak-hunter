# leak-hunter

<p align="center">
  <img src="public/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**Langues :** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter` est un CLI défensif et local-first pour détecter des secrets dans les repositories. Il fournit un binary multiplateforme unique capable de scanner des GitHub repository URLs, le raccourci `owner/repo`, des GitHub SSH targets ou des dossiers locaux, puis de produire des rapports Text, JSON ou Markdown.

Le crate Rust est l'unique implémentation cœur. Le npm package `leak-hunter` est un thin wrapper qui installe et exécute le native binary produit par cargo-dist dans GitHub Releases.

## Installation

```bash
cargo install --path .
```

Ou avec le npm package :

```bash
npm install -g leak-hunter
leak-hunter --help
```

## Démarrage rapide

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

GitHub targets pris en charge :

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## Options CLI

| Option | Description |
|---|---|
| `--json` | Produit du JSON machine-readable ; raccourci pour les JSON reports. |
| `--format <text\|json\|markdown>` | Choisit le format du rapport. |
| `--output <path>` | Écrit le rapport dans un fichier et crée les dossiers parents si nécessaire. |
| `--min-risk <0-100>` | Affiche uniquement les findings au-dessus du seuil de risque. |
| `--include <glob>` / `--exclude <glob>` | Limite le périmètre du scan ; peut être répété. |
| `--no-default-exclude` | Désactive les règles d'exclusion intégrées. |
| `--max-file-size-mb <n>` | Définit la taille maximale scannée par fichier. |
| `--concurrency <n>` | Définit le nombre de fichiers scannés en parallèle. |
| `--no-redact` | Affiche les valeurs brutes des secrets ; à réserver à une revue manuelle locale. |
| `--keep-temp` | Conserve les temporary clones des GitHub targets. |
| `--cache-dir <dir>` | Définit le dossier de temporary clone GitHub ; défaut : `.leak-hunter-cache`. |
| `--branch <name>` | Scanne une branch ou un tag spécifique. |
| `--debug` | Écrit dans stderr les décisions de scan, scores des candidate findings et raisons de filtrage min-risk. |
| `-v, --version` | Affiche les informations de version. |

`--json` et un `--format` explicite sont mutuellement exclusifs afin d'éviter une sortie ambiguë dans les scripts CI.

## Rapports

Les Text reports sont conçus pour une lecture directe dans le terminal :

```bash
leak-hunter . --format text
```

Le rapport commence par la bannière ASCII Leak Hunter et inclut la target, la scan root résolue, l'heure du scan, les nombres de fichiers scannés et ignorés, le nombre de findings, les risk buckets, l'état de redaction et une table de findings.

Les JSON reports conviennent aux artefacts CI, au traitement avec `jq` et aux intégrations :

```bash
leak-hunter . --json --output leak-hunter-report.json
```

Exemple pour extraire les findings à haut risque :

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## Stratégie de scan

1. Résoudre la target locale ou GitHub.
2. Cloner les GitHub repositories dans `.leak-hunter-cache` ou le dossier indiqué par `--cache-dir`.
3. Parcourir les fichiers avec un walker compatible gitignore et des include / exclude globs.
4. Ignorer les binary files ou les fichiers dépassant la limite configurée.
5. Appliquer le pattern inventory intégré et le context-aware risk model.
6. Réduire le noise courant provenant des npm integrity hashes dans package-lock, du contexte Firebase public API key et des chemins docs/example.
7. Redacter par défaut, puis trier la sortie par risk score, path et position.
8. Supprimer les temporary GitHub clones sauf si `--keep-temp` est défini.

## Points forts de détection

Les rules reconstruites couvrent actuellement :

- OpenAI, Google API Key, GitHub Token, Stripe, Slack, Sentry et Docker Hub PAT
- AWS access key / secret key pairing
- Azure Storage connection string / AccountKey / SAS URI
- Popular framework app secrets comme Django, Flask, Rails, Laravel, NextAuth, Nuxt, Spring et ASP.NET
- Database connection strings and URIs comme SQL Server-style connection string, PostgreSQL, MongoDB et Redis
- JWT, PEM private key, GCP service account JSON et Google OAuth client secret

## npm package et checksum

`npm/postinstall.cjs` associe la plateforme courante à une target cargo-dist, télécharge la release archive et son fichier `.sha256`, vérifie le checksum SHA-256, puis extrait et installe le native binary. La publication npm utilise Trusted Publishing / OIDC plutôt qu'un `NPM_TOKEN` longue durée. Avant publication, `prepublishOnly` exécute les tests npm, `npm pack --dry-run`, puis vérifie que chaque release archive et checksum existe.

## Développement

```bash
cargo fmt --all -- --check
cargo test
cargo build --release
npm test
npm pack --dry-run
```

Self-scan :

```bash
cargo run --quiet -- --json --min-risk 40 . \
  | jq '{findings: .summary.findings, filesEnumerated: .summary.filesEnumerated}'
```

## Sécurité

La redaction est activée par défaut. Ne publiez pas de rapports non redacted. Les test fixtures doivent utiliser des synthetic values assemblées à partir de fragments de chaînes afin de ne pas déclencher GitHub push protection.
