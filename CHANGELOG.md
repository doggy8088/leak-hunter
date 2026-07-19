# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.3] - 2026-07-19

### Fixed

- Prevent the Taiwan mobile-number detector from joining timestamp digits across line boundaries while preserving supported spaces and hyphens within a single line.
- Avoid npm 11 lifecycle-script approval warnings during `make install-npm-local` by running the native-binary postinstall step explicitly before creating the global link with lifecycle scripts disabled.

## [0.5.2] - 2026-07-19

### Fixed

- Treat readable lowercase word tokens in files named exactly `.env.example`, such as `sk-local-validation-only`, as low-risk placeholders while preserving normal scoring in other environment files.

## [0.5.1] - 2026-07-19

### Changed

- Findings in files named exactly `.env.example` now receive a 25-point risk reduction instead of the environment-file boost.

### Fixed

- Suppress PostgreSQL URIs in `compose.yaml` when their username, password, and database components are environment-variable interpolations, while preserving findings for literal credentials.
- Exclude runtime function and method call expressions assigned to password fields from `generic_password_context` findings across source file types.

## [0.5.0] - 2026-07-18

### Added

- High-confidence and context-gated detectors for GitLab, npm, PyPI, DigitalOcean, HashiCorp Vault, Doppler, Shopify, Square, Airtable, Braintree, Mailchimp, Slack and Discord webhooks, Telegram bot tokens, Cloudflare, Snyk, Sonar, PayPal, Notion, Mailgun, Postmark, Netlify, and Microsoft Teams webhook formats.
- Context-aware `generic_password_context` detection for random-looking values following complete `password`, `passwd`, or `pwd` labels in common text, Markdown, JSON, and YAML-style formats.
- Candidate validation for generic password fields using length, ASCII, character-class diversity, distinct-character count, and Shannon entropy requirements, with false-positive filtering for URLs, source-code constructs, identifiers, multiline content, and low-randomness values.
- A development Makefile covering formatting, linting, tests, builds, npm packaging, documentation builds, self-scans, parameterized scans, and local Cargo or npm installation.

### Changed

- Generic password findings use a base risk score of `65`, while placeholders, template references, and weak example values are retained as low-risk findings at `30`.
- Generic password findings are always fully replaced with `[REDACTED]` in the default output instead of retaining candidate prefixes or suffixes.
- Shannon entropy calculation is shared between pattern validation and scanner risk scoring.

### Fixed

- The npm CLI wrapper is now executable after checkout and packaging.
- Bare identifiers and code-like expressions that resemble provider tokens or password assignments no longer produce generic password findings.

## [0.4.0] - 2026-05-21

### Added

- Local-first repository secret scanning for folders, GitHub repository URLs, `owner/repo` shorthand, and GitHub SSH targets.
- Text, JSON, and Markdown report formats with redaction enabled by default.
- Numbered findings in Text reports for easier human review and counting.
- Configurable minimum risk threshold with `--min-risk`.
- Optional raw secret output with `--no-redact`.
- File output support with `--output`.
- Include and exclude glob filtering with default skips for generated dependency, build, cache, and target directories.
- `.leakhunterignore` support using `.gitignore` syntax for project-local scan exclusions.
- Debug output for scan decisions, candidate scores, and min-risk filtering reasons.
- Context-aware risk scoring using path, file type, documentation context, entropy, public-key/certificate context, Firebase context, local database URI context, Python `site-packages` context, and placeholder detection.
- Secret hashing for findings using stable redacted reports.
- Pattern coverage for major AI provider API keys, cloud/provider tokens, framework application secrets, database connection strings, PostgreSQL URIs, MongoDB URIs, Redis URIs, JWTs, SSH private keys, Azure SAS URIs, Google OAuth client secrets, and GCP service account JSON.
- Taiwan personal-data patterns for National ID, UI/ARC/APRC numbers, mobile phone numbers, e-invoice mobile barcodes, and citizen digital certificate numbers.
- Validation and false-positive filtering for Taiwan National ID, Taiwan UI/ARC/APRC, Taiwan e-invoice mobile barcodes, Azure SAS URIs, and database connection strings.
- npm package wrapper that installs the native binary from cargo-dist GitHub Release artifacts.
- Cross-platform cargo-dist release targets for macOS arm64, macOS x64, Linux x64, and Windows x64.
- npm prepublish checks for expected release assets and checksum files.
- Localized READMEs and static website assets.

### Changed

- `lib/python*/site-packages/**` findings now start from a low base score of `20`, because PyPI package files are third-party package content rather than project source.
- Hostless PostgreSQL URIs such as `postgres:///db_name` now score as low risk.
- Localhost database URIs now receive lower risk scoring.
- Redis localhost URIs now receive lower risk scoring.
- Taiwan mobile number scoring now distinguishes strict formats from incomplete space-separated formats.
- Placeholder connection strings with bracketed password placeholders such as `Password=<password>` now score as low risk.
- Text reports now prefix every finding with a sequential number.

### Fixed

- Avoid extracting Taiwan mobile numbers from the middle of alphanumeric tokens such as OpenSSL/BIO diagnostic codes.
- Reduce false positives for placeholder database connection strings and password examples.
- Reduce false positives for Azure SAS URI examples while preserving real SAS token detection.
- Reduce false positives for package-lock npm integrity hashes.
- Reduce false positives for Firebase public Google API key configuration.
- Reduce false positives for Taiwan e-invoice mobile barcodes.

## [0.3.0] - 2026-05-20

- Release baseline before this changelog was introduced.
