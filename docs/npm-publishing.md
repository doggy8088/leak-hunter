# npm publishing

The npm package is published as `leak-hunter` and exposes the `leak-hunter` binary.

Publishing uses GitHub Actions OIDC Trusted Publishing. Do not add long-lived npm tokens such as `NPM_TOKEN`.

Before `npm publish` completes, `prepublishOnly` runs npm tests, validates
`npm pack --dry-run`, and checks that the GitHub Release contains every
cargo-dist archive and `.sha256` file required by `npm/postinstall.cjs`.
