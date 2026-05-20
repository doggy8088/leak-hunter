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
fn detects_major_ai_provider_api_keys() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("ai.env"),
        [
            "ANTHROPIC_API_KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefghijklmnopqrstuvwxyz\n",
            "XAI_API_KEY=xai-AbCdEfGhIjKlMnOpQrStUvWxYz123456\n",
            "GROQ_API_KEY=gsk_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890\n",
            "OPENROUTER_API_KEY=sk-or-v1-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890\n",
            "REPLICATE_API_TOKEN=r8_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890\n",
            "HUGGINGFACE_TOKEN=hf_AbCdEfGhIjKlMnOpQrStUvWxYz123456\n",
        ]
        .concat(),
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let finding_types: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.finding_type.as_str())
        .collect();

    for expected in [
        "anthropic_api_key",
        "xai_api_key",
        "groq_api_key",
        "openrouter_api_key",
        "replicate_api_token",
        "huggingface_token",
    ] {
        assert!(finding_types.contains(&expected));
    }
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
            "ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
            "GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
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
fn scores_hostless_postgres_uri_as_low_risk() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("dataset.py"),
        "ds = Dataset.from_sql(\"test_data\", \"postgres:///db_name\")\n",
    )
    .unwrap();

    let mut opts = options();
    opts.min_risk = 0;
    opts.redact = false;
    let result = scan_path(dir.path(), &opts).unwrap();
    let finding = result
        .findings
        .iter()
        .find(|f| f.finding_type == "postgres_uri" && f.secret == "postgres:///db_name")
        .expect("expected hostless postgres URI finding");

    assert_eq!(finding.risk_score, 20);
}

#[test]
fn lowers_redis_localhost_uri_risk() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("runtime.txt"),
        "export REDIS_URL=\"redis://localhost:6379\"\n",
    )
    .unwrap();

    let mut opts = options();
    opts.min_risk = 0;
    let result = scan_path(dir.path(), &opts).unwrap();
    let finding = result
        .findings
        .iter()
        .find(|f| f.finding_type == "redis_uri")
        .expect("expected redis localhost URI finding");

    assert_eq!(finding.risk_score, 60);
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
fn lowers_risk_for_python_site_packages_files() {
    let dir = tempfile::tempdir().unwrap();
    let package_dir = dir.path().join("lib/python3.11/site-packages/vendor_pkg");
    std::fs::create_dir_all(&package_dir).unwrap();
    let secret = ["sk-proj-", "abcDEFghiJKLmnopQRSTuvwxYZ123456"].concat();
    std::fs::write(
        dir.path().join("project_module.py"),
        format!("OPENAI_API_KEY={secret}\n"),
    )
    .unwrap();
    std::fs::write(
        package_dir.join("module.py"),
        format!("OPENAI_API_KEY={secret}\n"),
    )
    .unwrap();

    let mut opts = options();
    opts.min_risk = 0;
    let result = scan_path(dir.path(), &opts).unwrap();
    let site_packages_finding = result
        .findings
        .iter()
        .find(|f| f.file_path == "lib/python3.11/site-packages/vendor_pkg/module.py")
        .expect("expected site-packages finding");

    assert_eq!(site_packages_finding.risk_score, 20);
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

#[test]
fn test_database_connection_string_filtering_and_placeholders() {
    let dir = tempfile::tempdir().unwrap();

    // 1a. Placeholder: Password=your-password — should score 30 (Low) via is_likely_placeholder
    std::fs::write(
        dir.path().join("placeholder_conn_a.txt"),
        "Server=tcp:127.0.0.1;Database=MyDatabase;User Id=sa;Password=your-password;",
    )
    .unwrap();

    // 1b. Placeholder: Password=YourStrong@Passw0rd — well-known Docker example password
    //     Use the prefix-key form so the first regex branch fires: key=val;...Password=val;key=val
    std::fs::write(
        dir.path().join("placeholder_conn_b.txt"),
        "Server=localhost,1433;Database=dev;User Id=sa;Password=YourStrong@Passw0rd;TrustServerCertificate=true;",
    )
    .unwrap();

    // 2. C# code lines that merely mention Password should NOT be found as connection strings
    std::fs::write(
        dir.path().join("code_false_positives.cs"),
        "var hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password);\n\
         string newPassword = _tool.GetNewPassword();\n\
         var newUser = new EnterpriseUser { EnterpriseId = 123 };",
    )
    .unwrap();

    // min-risk 40: nothing shown (placeholders = 30, code lines = filtered out entirely)
    let mut opts = options();
    opts.min_risk = 40;
    let result = scan_path(dir.path(), &opts).unwrap();
    assert_eq!(
        result.findings.len(),
        0,
        "Expected 0 findings at min-risk 40, got {:?}",
        result.findings
    );

    // min-risk 30: exactly 2 placeholder connection string findings, each scored 30
    let mut opts_30 = options();
    opts_30.min_risk = 30;
    let result_30 = scan_path(dir.path(), &opts_30).unwrap();

    let conn_findings: Vec<_> = result_30
        .findings
        .iter()
        .filter(|f| f.finding_type == "database_connection_string")
        .collect();

    assert_eq!(
        conn_findings.len(),
        2,
        "Expected 2 placeholder conn-string findings at min-risk 30, got {:?}",
        conn_findings
    );
    for f in conn_findings {
        assert_eq!(
            f.risk_score, 30,
            "Placeholder conn-string should score 30, got {}",
            f.risk_score
        );
    }
}

#[test]
fn azure_sas_uri_detects_real_token_and_filters_false_positives() {
    let dir = tempfile::tempdir().unwrap();

    // 1. Real SAS URI — must be found (Critical)
    let real_sig = "okgvvstSI4fFkTnnYtQsPuE0l0MfHuEG9i%2BOXJ1J1j8%3D"; // synthetic, 40+ chars
    std::fs::write(
        dir.path().join("real_sas.env"),
        format!(
            "AZURE_BLOB_SAS_URL=https://myaccount.blob.core.windows.net/container?sv=2024-01-01&sp=racwl&sig={real_sig}\n"
        ),
    )
    .unwrap();

    // 2. Placeholder sig ("...") — must NOT be found
    std::fs::write(
        dir.path().join("placeholder_sig.ts"),
        "const AZURE_BLOB_SAS_URL = 'https://myaccount.blob.core.windows.net/container?sv=...&sig=...';\n",
    )
    .unwrap();

    // 3. YOUR_ACCOUNT hostname placeholder — must NOT be found
    std::fs::write(
        dir.path().join("placeholder_host.ts"),
        "const SAS = 'https://YOUR_ACCOUNT.blob.core.windows.net/short-urls?sv=2024&sig=...';\n",
    )
    .unwrap();

    // 4. Non-Azure domain with sv/sig params (e.g. Google Forms) — must NOT be found
    std::fs::write(
        dir.path().join("google_forms.html"),
        "<a href=\"https://docs.google.com/forms/d/e/abc?sv=v1&sig=xyz123\">feedback</a>\n",
    )
    .unwrap();

    // 5. Multi-line / broken SAS URL — must NOT be found
    std::fs::write(
        dir.path().join("broken_url.md"),
        "https://myaccount.blob.core.windows.net/container?sv=2024\n&sig=okgvvstSI4fFkTnnYtQsPuE0l0MfHuEG9i\n",
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let sas_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.finding_type == "azure_sas_uri")
        .collect();

    assert_eq!(
        sas_findings.len(),
        1,
        "Expected exactly 1 real SAS finding, got {:?}",
        sas_findings
    );
    assert!(
        sas_findings[0].risk_score >= 90,
        "Real SAS URI should be Critical (>=90), got {}",
        sas_findings[0].risk_score
    );
}
