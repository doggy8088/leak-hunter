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
fn detects_taiwan_national_id_with_valid_checksum() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("id.txt"),
        "My ID is A123456789, and another valid ID is A123456798.\nInvalid ID: A123456780, B123456789\n",
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.finding_type == "taiwan_national_id")
        .collect();

    // Only the two valid IDs should be detected
    assert_eq!(findings.len(), 2);

    // Test custom strict redaction (A123456789 -> A1…89)
    assert_eq!(findings[0].secret, "A1…89");
    assert_eq!(findings[1].secret, "A1…98");
}

#[test]
fn detects_taiwan_arc_ui_both_old_and_new_formats() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("arc.txt"),
        "Old ARC: FA12345670\nNew ARC: F801234564\nInvalid Old: FA12345678\nInvalid New: F801234567\n",
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.finding_type == "taiwan_arc_ui")
        .collect();

    // Only the two valid ARCs should be detected
    assert_eq!(findings.len(), 2);

    // Strict redaction check
    assert_eq!(findings[0].secret, "FA…70");
    assert_eq!(findings[1].secret, "F8…64");
}

#[test]
fn detects_taiwan_mobile_phone_in_various_formats() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("mobile.txt"),
        "Mobile numbers:\n0988123456\n+886988123456\n886988123456\n0988-123-456\n0988 123 456\n+886-988-123-456\n\nInvalid:\n0888123456\n098812345\n09881234567\n",
    )
    .unwrap();

    let result = scan_path(dir.path(), &options()).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.finding_type == "taiwan_mobile")
        .collect();

    // All six valid formats should be detected
    assert_eq!(findings.len(), 6);

    // Strict redaction check: e.g. "0988-123-456" -> "09…56" or "+886988123456" -> "+8…56"
    assert!(findings.iter().all(|f| f.secret.starts_with("09…")
        || f.secret.starts_with("+8…")
        || f.secret.starts_with("88…")));
    assert!(findings.iter().all(|f| f.secret.ends_with("56")));
}

#[test]
fn scores_strict_taiwan_mobile_formats_at_base_risk() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("numbers.txt"),
        [
            "0900-000000\n",
            "0900000000\n",
            "+886-900-000000\n",
            "+886900000000\n",
            "886900000000\n",
        ]
        .concat(),
    )
    .unwrap();

    let mut opts = options();
    opts.min_risk = 0;
    opts.redact = false;
    let result = scan_path(dir.path(), &opts).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.finding_type == "taiwan_mobile")
        .collect();

    assert_eq!(findings.len(), 5);
    assert!(findings.iter().all(|f| f.risk_score == 50));
}

#[test]
fn lowers_incomplete_taiwan_mobile_formats_by_ten() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("numbers.txt"),
        ["0900 000000\n", "0900 000 000\n", "+886 900 000000\n"].concat(),
    )
    .unwrap();

    let mut opts = options();
    opts.min_risk = 0;
    opts.redact = false;
    let result = scan_path(dir.path(), &opts).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.finding_type == "taiwan_mobile")
        .collect();

    assert_eq!(findings.len(), 3);
    assert!(findings.iter().all(|f| f.risk_score == 40));
}

#[test]
fn detects_taiwan_einvoice_barcode() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("barcode.txt"),
        "My barcode is /ABC+123 and carrier /1.+-A9Z.\nInvalid: /abc+123, ABC+123, /ABC+1234\nFalse Positives: /169.254, /127.0.0, /COPYALL\n",
    )
    .unwrap();

    // Base risk is 20 (Low), so use min_risk=0 to catch these findings
    let mut opts = options();
    opts.min_risk = 0;
    let result = scan_path(dir.path(), &opts).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.finding_type == "taiwan_einvoice_barcode")
        .collect();

    // Two valid barcodes should be detected (False positives should be correctly filtered out)
    assert_eq!(findings.len(), 2);
    // Base score is 20; context keyword "barcode" may add +15 → max 35. Still Low risk.
    assert!(
        findings.iter().all(|f| f.risk_score <= 35),
        "Expected risk_score <= 35, got: {:?}",
        findings.iter().map(|f| f.risk_score).collect::<Vec<_>>()
    );

    // Strict redaction check
    assert_eq!(findings[0].secret, "/A…23");
    assert_eq!(findings[1].secret, "/1…9Z");
}

#[test]
fn detects_taiwan_citizen_certificate() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("certificate.txt"),
        "Certificate: AB12345678901234\nInvalid: ab12345678901234, A123456789012345, ABC12345678901234\n",
    )
    .unwrap();

    // Base is now 30, so use min_risk=0 to capture it without any keyword context
    let mut opts = options();
    opts.min_risk = 0;
    let result = scan_path(dir.path(), &opts).unwrap();
    let findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.finding_type == "taiwan_citizen_certificate")
        .collect();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret, "AB…34");
    // No keywords in context → base score only
    assert_eq!(
        findings[0].risk_score, 30,
        "Without any keywords, citizen certificate should score 30 (base only)"
    );
}

#[test]
fn taiwan_citizen_certificate_additive_keyword_scoring() {
    let dir = tempfile::tempdir().unwrap();

    // 1. "自然人憑證" → base(30) + 自然人憑證(+30) + 自然人(+10) + 憑證(+10) = 80
    std::fs::write(
        dir.path().join("full_phrase.txt"),
        "自然人憑證號碼: AB12345678901234",
    )
    .unwrap();

    // 2. Only "自然人" → base(30) + 自然人(+10) = 40
    std::fs::write(
        dir.path().join("only_ziran.txt"),
        "這是自然人的資料 AB12345678901234",
    )
    .unwrap();

    // 3. Only "憑證" → base(30) + 憑證(+10) = 40
    std::fs::write(
        dir.path().join("only_cert.txt"),
        "憑證編號: AB12345678901234",
    )
    .unwrap();

    // 4. No keywords → base(30)
    std::fs::write(
        dir.path().join("no_kw.txt"),
        "Certificate number: AB12345678901234",
    )
    .unwrap();

    let mut opts = options();
    opts.min_risk = 0;
    let result = scan_path(dir.path(), &opts).unwrap();

    let get_score = |filename: &str| -> u8 {
        result
            .findings
            .iter()
            .find(|f| {
                f.finding_type == "taiwan_citizen_certificate" && f.file_path.contains(filename)
            })
            .map(|f| f.risk_score)
            .unwrap_or(0)
    };

    assert_eq!(
        get_score("full_phrase"),
        80,
        "自然人憑證 → 30+30+10+10 = 80"
    );
    assert_eq!(get_score("only_ziran"), 40, "自然人 only → 30+10 = 40");
    assert_eq!(get_score("only_cert"), 40, "憑證 only → 30+10 = 40");
    assert_eq!(get_score("no_kw"), 30, "no keywords → 30");
}

#[test]
fn applies_taiwan_pdpa_contextual_risk_boost() {
    let dir = tempfile::tempdir().unwrap();

    // 1. Without keywords
    std::fs::write(dir.path().join("no_kw.txt"), "A123456789").unwrap();

    // 2. With keywords (身分證)
    std::fs::write(dir.path().join("with_kw.txt"), "身分證: A123456789").unwrap();

    let mut opts = options();
    opts.redact = false; // Disable redaction to see raw or verify general behavior, but risk scores are independent of redact.

    let result_no = scan_path(dir.path(), &opts).unwrap();
    let finding_no = result_no
        .findings
        .iter()
        .find(|f| f.file_path.contains("no_kw"))
        .unwrap();
    assert_eq!(finding_no.risk_score, 85); // Base risk

    let result_with = scan_path(dir.path(), &opts).unwrap();
    let finding_with = result_with
        .findings
        .iter()
        .find(|f| f.file_path.contains("with_kw"))
        .unwrap();
    assert_eq!(finding_with.risk_score, 100); // 85 + 15 = 100
}
