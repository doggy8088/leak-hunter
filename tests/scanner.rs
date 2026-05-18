use leak_hunter::scanner::{scan_path, ScanOptions};

fn options() -> ScanOptions {
    ScanOptions {
        include: vec![],
        exclude: vec![],
        default_exclude: true,
        min_risk: 40,
        max_file_size_bytes: 1024 * 1024,
        concurrency: 1,
        redact: true,
        debug: false,
    }
}

#[test]
fn detects_split_openai_like_key_without_exposing_raw_value() {
    let dir = tempfile::tempdir().unwrap();
    let secret = ["sk-proj-", "abcDEFghiJKLmnopQRSTuvwxYZ123456"].concat();
    std::fs::write(
        dir.path().join("app.env"),
        format!("OPENAI_API_KEY={secret}\n"),
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    assert_eq!(result.summary.findings, 1);
    assert_eq!(result.findings[0].finding_type, "openai_api_key");
    assert_ne!(result.findings[0].secret, secret);
    assert!(result.findings[0].secret.contains('…'));
}

#[test]
fn skips_binary_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bin.dat"), b"abc\0def").unwrap();
    let result = scan_path(dir.path(), &options()).unwrap();
    assert_eq!(result.summary.skipped_binary, 1);
}
