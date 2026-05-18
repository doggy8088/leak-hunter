# Release packaging

Releases are built with cargo-dist. Cargo and npm versions must stay in sync.

Before tagging a release, run:

```bash
cargo fmt --all -- --check
cargo test
cargo build --release
dist plan
npm pack --dry-run
```
