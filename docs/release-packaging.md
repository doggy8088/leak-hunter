# Release packaging

Releases are built with cargo-dist. Cargo and npm versions must stay in sync.

Before tagging a release, run:

```bash
cargo fmt --all -- --check
cargo test
cargo build --release
dist plan
npm test
npm pack --dry-run
```

Run these commands with the cargo-dist version configured in `Cargo.toml`.

The checked-in GitHub release workflow began as cargo-dist output and contains
intentional project customizations. Because `ci` is listed in `allow-dirty`,
`dist generate --mode=ci --check` intentionally refuses to validate it. The
`dist_config` integration tests protect the required artifact flow instead.
Regenerate the workflow with the repository's configured cargo-dist version
only after changing `[workspace.metadata.dist]`, then review and restore the
project customizations before committing it.

The npm prepublish asset check is expected to fail before the matching GitHub
Release exists. It runs automatically during `npm publish` after cargo-dist has
uploaded the release archives and checksum files.
