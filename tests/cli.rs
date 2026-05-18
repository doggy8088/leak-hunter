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
