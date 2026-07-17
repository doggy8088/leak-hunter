use std::process::Command;

#[test]
fn help_prints_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .arg("--help")
        .output()
        .expect("run leak-hunter --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("-v, --version"));
}

#[test]
fn version_flags_print_package_version() {
    for flag in ["-v", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
            .arg(flag)
            .output()
            .expect("run leak-hunter version");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("leak-hunter"));
        assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn json_flag_rejects_explicit_format_to_avoid_ambiguity() {
    let output = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .args(["--json", "--format", "text"])
        .output()
        .expect("run leak-hunter");
    assert!(!output.status.success());
}

#[test]
fn json_scan_reports_no_findings_for_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .arg("--json")
        .arg(dir.path())
        .output()
        .expect("run leak-hunter");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["summary"]["findings"], 0);
}

#[test]
fn json_no_redact_outputs_raw_secret_and_warning() {
    let dir = tempfile::tempdir().unwrap();
    let secret = ["sk-proj-", "abcDEFghiJKLmnopQRSTuvwxYZ123456"].concat();
    std::fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={secret}\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .args(["--json", "--no-redact"])
        .arg(dir.path())
        .output()
        .expect("run leak-hunter");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains(&secret));
    assert!(stderr.contains("raw secret values"));
}

#[test]
fn output_file_is_written_and_warns_when_redaction_is_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let output_path = dir.path().join("reports/out.json");
    let secret = ["sk-proj-", "abcDEFghiJKLmnopQRSTuvwxYZ123456"].concat();
    std::fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={secret}\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .args(["--json", "--no-redact", "--output"])
        .arg(&output_path)
        .arg(dir.path())
        .output()
        .expect("run leak-hunter");
    assert_eq!(output.status.code(), Some(1));
    assert!(output_path.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("redaction disabled"));
}

#[test]
fn debug_flag_prints_scan_decisions_to_stderr_without_breaking_json_stdout() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "hello").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .args(["--json", "--debug"])
        .arg(dir.path())
        .output()
        .expect("run leak-hunter");
    assert!(output.status.success());
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("[debug]"));
}

#[test]
fn text_and_markdown_formats_scan_local_fixtures() {
    let dir = tempfile::tempdir().unwrap();
    let secret = ["sk-proj-", "abcDEFghiJKLmnopQRSTuvwxYZ123456"].concat();
    std::fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={secret}\n"),
    )
    .unwrap();

    let text = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .args(["--format", "text"])
        .arg(dir.path())
        .output()
        .expect("run text");
    assert_eq!(text.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.starts_with(" _                _"));
    assert!(stdout.contains("Leak Hunter Report\n=================="));
    assert!(stdout.contains("\n1. ["));

    let markdown = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .args(["--format", "markdown"])
        .arg(dir.path())
        .output()
        .expect("run markdown");
    assert_eq!(markdown.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&markdown.stdout).starts_with("# Leak Hunter Report"));
}

#[test]
fn generic_password_json_scan_reports_redacted_finding_and_failure_status() {
    let dir = tempfile::tempdir().unwrap();
    let label = ["Pass", "word"].concat();
    let value = ["aB3d", "E5fG", "7hJ9"].concat();
    std::fs::write(
        dir.path().join("credentials.md"),
        format!("> {label} : {value}\n"),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_leak-hunter"))
        .arg("--json")
        .arg(dir.path())
        .output()
        .expect("run generic password scan");

    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["type"] == "generic_password_context")
        .expect("expected generic password finding");
    assert!(finding["riskScore"].as_u64().unwrap() >= 40);
    assert_eq!(finding["secret"], "[REDACTED]");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&value));
}
