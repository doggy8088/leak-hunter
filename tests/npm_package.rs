#[test]
fn npm_publish_workflow_uses_trusted_publishing_and_updates_npm() {
    let workflow = std::fs::read_to_string(".github/workflows/npm-publish.yml").unwrap();
    assert!(workflow.contains("id-token: write"));
    assert!(workflow.contains("npm publish --provenance --access public"));
    assert!(!workflow.contains("NPM_TOKEN"));
}

#[test]
fn npm_package_metadata_matches_cargo_and_exposes_expected_bins() {
    let package = std::fs::read_to_string("package.json").unwrap();
    let cargo = std::fs::read_to_string("Cargo.toml").unwrap();
    assert!(package.contains("\"name\": \"@doggy8088/leak-hunter\""));
    assert!(package.contains("\"leak-hunter\": \"npm/cli.cjs\""));
    assert!(package.contains("\"version\": \"0.1.0\""));
    assert!(cargo.contains("version = \"0.1.0\""));
}

#[test]
fn npm_postinstall_maps_all_cargo_dist_targets() {
    let script = std::fs::read_to_string("npm/postinstall.cjs").unwrap();
    for target in [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ] {
        assert!(script.contains(target));
    }
}

#[test]
fn npm_postinstall_downloads_and_verifies_release_checksums() {
    let script = std::fs::read_to_string("npm/postinstall.cjs").unwrap();
    assert!(script.contains(".sha256"));
    assert!(script.contains("verifyChecksum"));
    assert!(script.contains("Checksum mismatch"));
}
