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
fn detects_common_developer_and_saas_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let gitlab = ["glpat-", "AbCdEfGhIjKlMnOpQrStUvWxYz1234"].concat();
    let npm = ["npm_", "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"].concat();
    let pypi = [
        "pypi-",
        "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefghijklmno",
    ]
    .concat();
    let digitalocean = ["dop_v1_", "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD"].concat();
    let vault = ["hvs.", "AbCdEfGhIjKlMnOpQrStUvWxYz123456"].concat();
    let doppler = ["dp.pt.", "AbCdEfGhIjKlMnOpQrStUvWxYz123456"].concat();
    let shopify = ["shpat_", "AbCdEfGhIjKlMnOpQrStUvWxYz123456"].concat();
    let square_access = ["sq0atp-", "AbCdEfGhIjKlMnOpQrStUvWxYz123456"].concat();
    let square_secret = ["sq0csp-", "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"].concat();
    let airtable = [
        "patAbCdEfGhIjKlMn.",
        "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD",
    ]
    .concat();
    let braintree = [
        "access_token$production$merchant123$",
        "AbCdEfGhIjKlMnOpQrStUvWxYz123456",
    ]
    .concat();
    let mailchimp = ["0123456789abcdef0123456789abcdef", "-us20"].concat();

    std::fs::write(
        dir.path().join("tokens.env"),
        format!(
            "\
GITLAB_TOKEN={gitlab}
NPM_TOKEN={npm}
PYPI_API_TOKEN={pypi}
DIGITALOCEAN_TOKEN={digitalocean}
VAULT_TOKEN_NEW={vault}
DOPPLER_TOKEN={doppler}
SHOPIFY_TOKEN={shopify}
SQUARE_ACCESS_TOKEN={square_access}
SQUARE_APPLICATION_SECRET={square_secret}
AIRTABLE_TOKEN={airtable}
BRAINTREE_TOKEN={braintree}
MAILCHIMP_API_KEY={mailchimp}
"
        ),
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let finding_types: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.finding_type.as_str())
        .collect();

    for expected in [
        "gitlab_token",
        "npm_token",
        "pypi_api_token",
        "digitalocean_token",
        "hashicorp_vault_token",
        "doppler_token",
        "shopify_access_token",
        "square_access_token",
        "square_application_secret",
        "airtable_pat",
        "braintree_access_token",
        "mailchimp_api_key",
    ] {
        assert!(finding_types.contains(&expected), "missing {expected}");
    }
}

#[test]
fn detects_common_webhook_and_context_gated_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let slack_webhook = [
        "https://hooks.slack.com/services/T1234567890/B1234567890/",
        "AbCdEfGhIjKlMnOpQrStUvWxYz1234",
    ]
    .concat();
    let discord_webhook = [
        "https://discord.com/api/webhooks/123456789012345678/",
        "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefghijklmnoPQRSTUVWXYZ",
    ]
    .concat();
    let telegram = ["123456789:", "AbCdEfGhIjKlMnOpQrStUvWxYz123456789"].concat();
    let cloudflare = ["v1.0-", "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD"].concat();
    let vault_legacy = ["s.", "AbCdEfGhIjKlMnOpQrStUvWxYz"].concat();
    let paypal = ["AbCdEfGhIjKlMnOpQrStUvWxYz123456"].concat();
    let notion = ["secret_", "AbCdEfGhIjKlMnOpQrStUvWxYz"].concat();
    let netlify = ["AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD"].concat();
    let teams_webhook = [
        "https://example.webhook.office.com/webhookb2/",
        "01234567-89ab-cdef-0123-456789abcdef@01234567-89ab-cdef-0123-456789abcdef/",
        "IncomingWebhook/AbCdEfGhIjKlMnOpQrStUvWxYz/",
        "01234567-89ab-cdef-0123-456789abcdef",
    ]
    .concat();
    let teams_logic = [
        "https://prod-00.eastus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?",
        "api-version=2016-10-01&sig=AbCdEfGhIjKlMnOpQrStUvWxYz123456",
    ]
    .concat();

    std::fs::write(
        dir.path().join("webhooks.env"),
        format!(
            "\
SLACK_WEBHOOK_URL={slack_webhook}
DISCORD_WEBHOOK_URL={discord_webhook}
TELEGRAM_BOT_TOKEN={telegram}
CLOUDFLARE_API_TOKEN={cloudflare}
VAULT_TOKEN={vault_legacy}
SNYK_TOKEN=123e4567-e89b-12d3-a456-426614174000
SONAR_TOKEN=0123456789abcdef0123456789abcdef01234567
PAYPAL_CLIENT_SECRET={paypal}
NOTION_API_TOKEN={notion}
MAILGUN_API_KEY=key-0123456789abcdef0123456789abcdef
POSTMARK_SERVER_API_TOKEN=123e4567-e89b-12d3-a456-426614174000
NETLIFY_AUTH_TOKEN={netlify}
TEAMS_WEBHOOK_URL={teams_webhook}
MICROSOFT_TEAMS_WEBHOOK_URL={teams_logic}
"
        ),
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let finding_types: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.finding_type.as_str())
        .collect();

    for expected in [
        "slack_webhook_url",
        "discord_webhook_url",
        "telegram_bot_token",
        "cloudflare_api_token_context",
        "vault_legacy_token_context",
        "snyk_token_context",
        "sonar_token_context",
        "paypal_client_secret_context",
        "notion_token_context",
        "mailgun_api_key_context",
        "postmark_api_token_context",
        "netlify_auth_token_context",
        "microsoft_teams_webhook_url",
        "teams_logic_webhook_context",
    ] {
        assert!(finding_types.contains(&expected), "missing {expected}");
    }
}

#[test]
fn context_gated_tokens_do_not_match_bare_common_identifiers() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("ids.txt"),
        [
            "uuid = 123e4567-e89b-12d3-a456-426614174000\n",
            "sha1 = 0123456789abcdef0123456789abcdef01234567\n",
            "notion_like = secret_AbCdEfGhIjKlMnOpQrStUvWxYz\n",
            "mailgun_like = key-0123456789abcdef0123456789abcdef\n",
            "vault_note = s.AbCdEfGhIjKlMnOpQrStUvWxYz\n",
        ]
        .concat(),
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    assert_eq!(result.summary.findings, 0);
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
fn leakhunterignore_filters_files_with_gitignore_syntax() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".leakhunterignore"), "*.env\n!kept.env\n").unwrap();
    let ignored_secret = ["sk-proj-", "ignoredSECRETvalue1234567890"].concat();
    let kept_secret = ["sk-proj-", "keptSECRETvalue1234567890ABC"].concat();
    std::fs::write(
        dir.path().join("ignored.env"),
        format!("OPENAI_API_KEY={ignored_secret}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("kept.env"),
        format!("OPENAI_API_KEY={kept_secret}\n"),
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    assert_eq!(result.summary.findings, 1);
    assert_eq!(result.findings[0].file_path, "kept.env");
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
fn suppresses_env_interpolated_postgres_uri_in_compose_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let contents = "DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}\n";
    std::fs::write(dir.path().join("compose.yaml"), contents).unwrap();
    std::fs::write(dir.path().join("config.yaml"), contents).unwrap();

    let mut opts = options();
    opts.min_risk = 0;
    let result = scan_path(dir.path(), &opts).unwrap();

    assert_eq!(result.summary.findings, 1);
    assert_eq!(result.findings[0].finding_type, "postgres_uri");
    assert_eq!(result.findings[0].file_path, "config.yaml");
}

#[test]
fn detects_literal_postgres_credentials_in_compose_yaml() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yaml"),
        "DATABASE_URL: postgresql://app_user:synthetic_password_1234@postgres:5432/app_db\n",
    )
    .unwrap();

    let mut opts = options();
    opts.min_risk = 0;
    let result = scan_path(dir.path(), &opts).unwrap();
    let postgres_findings = result
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "postgres_uri")
        .count();

    assert_eq!(postgres_findings, 1);
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
fn lowers_risk_for_env_example_files() {
    let dir = tempfile::tempdir().unwrap();
    let secret = ["sk-proj-", "abcDEFghiJKLmnopQRSTuvwxYZ123456"].concat();
    for file_name in ["app.env", ".env.example", ".env.example.local"] {
        std::fs::write(
            dir.path().join(file_name),
            format!("OPENAI_API_KEY={secret}\n"),
        )
        .unwrap();
    }

    let mut opts = options();
    opts.min_risk = 0;
    let result = scan_path(dir.path(), &opts).unwrap();
    let score_for = |file_name: &str| {
        result
            .findings
            .iter()
            .find(|finding| finding.file_path == file_name)
            .map(|finding| finding.risk_score)
            .unwrap_or_else(|| panic!("expected finding in {file_name}"))
    };

    assert_eq!(score_for("app.env"), 98);
    assert_eq!(score_for(".env.example"), 65);
    assert_eq!(score_for(".env.example.local"), 98);
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

    // 1c. Angle-bracket placeholder: Password=<password> — should score 20 (Low)
    std::fs::write(
        dir.path().join("placeholder_conn_c.md"),
        "Server=<host>,<port>;Database=CMS;User Id=<user>;Password=<password>;Encrypt=True;TrustServerCertificate=True",
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

    // min-risk 20: include the angle-bracket placeholder connection string, scored 20
    let mut opts_20 = options();
    opts_20.min_risk = 20;
    let result_20 = scan_path(dir.path(), &opts_20).unwrap();
    let bracketed_placeholder = result_20
        .findings
        .iter()
        .find(|f| f.file_path == "placeholder_conn_c.md")
        .expect("Expected angle-bracket placeholder connection string finding");
    assert_eq!(bracketed_placeholder.risk_score, 20);
}

#[test]
fn generic_password_detects_markdown_blockquote_values_with_default_risk() {
    let dir = tempfile::tempdir().unwrap();
    let label = ["Pass", "word"].concat();
    let values = [
        ["aB3d", "E5fG", "7hJ9"].concat(),
        ["LmNo", "PqRs", "TuVw"].concat(),
        ["ZxCv", "BnMm", "KjHg"].concat(),
    ];
    let contents = values
        .iter()
        .map(|value| format!("> {label} : {value}\n"))
        .collect::<String>();
    std::fs::write(dir.path().join("credentials.md"), contents).unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "generic_password_context")
        .collect();

    assert_eq!(findings.len(), 3);
    for (index, finding) in findings.iter().enumerate() {
        assert_eq!(finding.risk_score, 65);
        assert_eq!(finding.secret, "[REDACTED]");
        assert_eq!(finding.line_number, index + 1);
        assert!(finding.entropy >= 3.0);
        assert!(finding.secret_hash.starts_with("sha256:"));
        assert!(values.iter().all(|value| !finding.snippet.contains(value)));
    }
}

#[test]
fn generic_password_supports_common_labels_and_serialized_forms() {
    let dir = tempfile::tempdir().unwrap();
    let password = ["Pass", "word"].concat();
    let upper_password = password.to_ascii_uppercase();
    let values = [
        ["Q1wE", "3rT5", "yU7i"].concat(),
        ["AsDf", "GhJk", "LqWe"].concat(),
        ["Z9xC", "8vB7", "nM6k"].concat(),
        ["R2tY", "4uI6", "oP8a"].concat(),
        ["HjKl", "QwEr", "TyUi"].concat(),
        ["MyPass", "word", "123!"].concat(),
    ];
    let contents = [
        format!("- **{password}:** '{}'\n", values[0]),
        format!("{upper_password}={}\n", values[1]),
        format!("passwd : `{}`\n", values[2]),
        format!("PWD = '{}'\n", values[3]),
        format!("\"{}\": \"{}\"\n", password.to_ascii_lowercase(), values[4]),
        format!("{password}: {}\n", values[5]),
    ]
    .concat();
    std::fs::write(dir.path().join("formats.txt"), contents).unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "generic_password_context")
        .collect();

    assert_eq!(findings.len(), values.len());
    assert!(findings.iter().all(|finding| finding.risk_score == 65));
}

#[test]
fn generic_password_remains_visible_in_documentation_paths() {
    let dir = tempfile::tempdir().unwrap();
    let docs = dir.path().join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    let label = ["Pass", "word"].concat();
    let value = ["aB3d", "E5fG", "7hJ9"].concat();
    std::fs::write(docs.join("credentials.md"), format!("> {label}: {value}\n")).unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.finding_type == "generic_password_context")
        .expect("expected generic password finding in docs path");

    assert_eq!(finding.risk_score, 40);
}

#[test]
fn generic_password_scores_placeholders_below_the_default_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let label = ["Pass", "word"].concat();
    let placeholders = ["your-password", "${PASSWORD}", "{{PASSWORD}}", "%PASSWORD%"];
    let contents = placeholders
        .iter()
        .map(|value| format!("{label}: {value}\n"))
        .collect::<String>();
    std::fs::write(dir.path().join("placeholders.txt"), contents).unwrap();

    let default_result = scan_path(dir.path(), &options()).unwrap();
    assert!(default_result
        .findings
        .iter()
        .all(|finding| finding.finding_type != "generic_password_context"));

    let mut low_risk_options = options();
    low_risk_options.min_risk = 30;
    let low_risk_result = scan_path(dir.path(), &low_risk_options).unwrap();
    let findings: Vec<_> = low_risk_result
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "generic_password_context")
        .collect();

    assert_eq!(findings.len(), placeholders.len());
    assert!(findings.iter().all(|finding| finding.risk_score == 30));
}

#[test]
fn generic_password_rejects_code_references_and_non_random_values() {
    let dir = tempfile::tempdir().unwrap();
    let label = ["Pass", "word"].concat();
    let overlong = "A1".repeat(65);
    let contents = [
        format!("{label}: form.password\n"),
        format!("{label}: passwordHash\n"),
        format!("{label}: getPassword()\n"),
        format!("{label}: https://example.invalid/login\n"),
        format!("{label}: reset your password now\n"),
        format!("{label}: abcdefghijk\n"),
        format!("{label}: A1A1A1A1A1A1\n"),
        format!("{label}: 非ASCII候選值123\n"),
        format!("{label}: {overlong}\n"),
        format!("{label}:\n{}\n", ["aB3d", "E5fG", "7hJ9"].concat()),
    ]
    .concat();
    std::fs::write(dir.path().join("false-positives.txt"), contents).unwrap();

    let mut all_risks = options();
    all_risks.min_risk = 0;
    let result = scan_path(dir.path(), &all_risks).unwrap();

    let unexpected: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "generic_password_context")
        .map(|finding| {
            (
                finding.finding_type.as_str(),
                finding.line_number,
                finding.risk_score,
            )
        })
        .collect();
    assert!(unexpected.is_empty(), "unexpected findings: {unexpected:?}");
}

#[test]
fn generic_password_rejects_runtime_code_expressions_in_any_file_type() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        ("generator.py", "password = secrets.token_urlsafe(32)\n"),
        ("generator.js", "password = crypto.randomBytes(32)\n"),
        ("generator.rb", "password = SecureRandom.hex(32)\n"),
        ("generator.go", "password = generatePassword(32)\n"),
        ("generator.rs", "password = rand::random(32)\n"),
        ("generator.php", "password = random_bytes(32)\n"),
    ];
    for (file_name, contents) in cases {
        std::fs::write(dir.path().join(file_name), contents).unwrap();
    }

    let literal = ["aB3d", "E5fG", "7hJ9"].concat();
    std::fs::write(
        dir.path().join("literal.py"),
        format!("password = '{literal}'\n"),
    )
    .unwrap();

    let mut all_risks = options();
    all_risks.min_risk = 0;
    let result = scan_path(dir.path(), &all_risks).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "generic_password_context")
        .collect();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].file_path, "literal.py");
    assert_eq!(findings[0].risk_score, 65);
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
