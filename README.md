# leak-hunter

`leak-hunter` is a cross-platform repository secret scanner written in Rust. It scans local folders or GitHub repositories and reports likely leaked credentials with safe redaction enabled by default.

## Install

```bash
cargo install --path .
```

The npm package `@doggy8088/leak-hunter` is a thin wrapper that downloads the native binary from GitHub Releases.

## Usage

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

Common options:

- `--json`: emit machine-readable JSON.
- `--min-risk <0-100>`: only report findings at or above the threshold.
- `--include <glob>` / `--exclude <glob>`: narrow scan scope.
- `--no-redact`: include raw values. Use only for local triage.
- `--keep-temp`: keep temporary GitHub clones.
- `--branch <name>`: scan a specific branch or tag.

## Safety

Redaction is enabled by default. Do not publish unredacted reports. Test fixtures should use split or clearly fake values so GitHub push protection is not triggered.

## Development

```bash
cargo fmt --all -- --check
cargo test
cargo build --release
npm pack --dry-run
```
