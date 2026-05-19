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
    assert!(result.findings[0].entropy > 3.0);
}

#[test]
fn suppresses_prefixed_keys_with_repeated_placeholder_body() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.env"),
        [
            "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx\n",
            "OPENAI_PROJECT_API_KEY=sk-proj-xxxx-xxxx-xxxx-xxxx\n",
            "GOOGLE_API_KEY=AIzaxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
            "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx\n",
            "AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX\n",
        ]
        .concat(),
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    assert_eq!(result.summary.findings, 0);
}

#[test]
fn skips_binary_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bin.dat"), b"abc\0def").unwrap();
    let result = scan_path(dir.path(), &options()).unwrap();
    assert_eq!(result.summary.skipped_binary, 1);
}

#[test]
fn detects_database_connection_strings_with_passwords_as_medium_risk() {
    let dir = tempfile::tempdir().unwrap();
    let conn = [
        "Server=db;User Id=app;",
        "Pass",
        "word=correct-horse-battery;Database=app",
    ]
    .concat();
    std::fs::write(
        dir.path().join("appsettings.Production.json"),
        format!(r#"{{"ConnectionStrings":{{"Main":"{conn}"}}}}"#),
    )
    .unwrap();
    let result = scan_path(dir.path(), &options()).unwrap();
    assert!(result
        .findings
        .iter()
        .any(|f| f.finding_type == "database_connection_string" && f.risk_score >= 50));
}

#[test]
fn detects_framework_application_secrets_in_popular_framework_configs() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("config")).unwrap();
    let value = ["abcdefghijklmnop", "qrstuvwxyz123456"].concat();
    let key = ["SECRET", "_KEY_BASE"].concat();
    std::fs::write(
        dir.path().join("config/application.yml"),
        format!("{key}={value}\n"),
    )
    .unwrap();
    let result = scan_path(dir.path(), &options()).unwrap();
    assert!(result
        .findings
        .iter()
        .any(|f| f.finding_type == "framework_app_secret_context"));
}

#[test]
fn suppresses_npm_integrity_hashes_that_look_like_azure_storage_keys() {
    let dir = tempfile::tempdir().unwrap();
    let fake_hash = "A".repeat(86) + "==";
    std::fs::write(
        dir.path().join("package-lock.json"),
        format!(r#"{{"packages":{{"":{{"integrity":"sha512-{fake_hash}"}}}}}}"#),
    )
    .unwrap();
    let result = scan_path(dir.path(), &options()).unwrap();
    assert_eq!(result.summary.findings, 0);
}

#[test]
fn lowers_google_api_key_risk_in_firebase_context() {
    let dir = tempfile::tempdir().unwrap();
    let key = ["AIza", "abcdefghijklmnopqrstuvwxyzABCDEFGHI"].concat();
    std::fs::write(
        dir.path().join("firebase-config.js"),
        format!("const firebaseConfig = {{ apiKey: '{key}' }};\n"),
    )
    .unwrap();
    let mut opts = options();
    opts.min_risk = 40;
    let result = scan_path(dir.path(), &opts).unwrap();
    assert_eq!(result.summary.findings, 0);
}

#[test]
fn include_exclude_and_skip_accounting_match_options() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
    std::fs::write(dir.path().join("b.log"), "hello").unwrap();
    std::fs::write(dir.path().join("big.txt"), "x".repeat(20)).unwrap();
    let mut opts = options();
    opts.include = vec!["**/*.txt".into()];
    opts.exclude = vec!["a.txt".into()];
    opts.max_file_size_bytes = 10;
    let result = scan_path(dir.path(), &opts).unwrap();
    assert_eq!(result.summary.files_enumerated, 1);
    assert_eq!(result.summary.skipped_too_large, 1);
}
