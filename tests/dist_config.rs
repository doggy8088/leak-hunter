#[test]
fn cargo_dist_targets_cover_primary_desktop_and_server_platforms() {
    let cargo = std::fs::read_to_string("Cargo.toml").unwrap();
    for target in [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ] {
        assert!(cargo.contains(target), "missing cargo-dist target {target}");
    }
    assert!(cargo.contains("installers"));
    assert!(cargo.contains("npm"));
}

#[test]
fn release_workflow_uses_cargo_dist_for_each_configured_target() {
    let workflow = std::fs::read_to_string(".github/workflows/release.yml").unwrap();
    assert!(workflow.contains("cargo-dist"));
    for target in [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ] {
        assert!(
            workflow.contains(target),
            "release workflow missing {target}"
        );
    }
}
