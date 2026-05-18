# Architecture

`leak-hunter` is a Rust CLI with five main modules:

- `cli`: parses arguments and orchestrates scans.
- `target`: resolves local paths and GitHub repository targets.
- `scanner`: walks files, applies excludes, detects likely secrets, redacts output.
- `patterns`: contains built-in regex-based detection rules.
- `formatters`: emits text, JSON, and Markdown reports.

The npm package is intentionally a thin wrapper around the native binary produced by cargo-dist.
