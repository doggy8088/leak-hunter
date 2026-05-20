use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub id: &'static str,
    pub title: &'static str,
    pub regex: Regex,
    pub base_risk: u8,
    pub validator: Option<fn(&str) -> bool>,
}

impl SecretPattern {
    fn new(id: &'static str, title: &'static str, pattern: &'static str, base_risk: u8) -> Self {
        Self {
            id,
            title,
            regex: Regex::new(pattern).expect("built-in regex must compile"),
            base_risk,
            validator: None,
        }
    }

    fn new_with_validator(
        id: &'static str,
        title: &'static str,
        pattern: &'static str,
        base_risk: u8,
        validator: fn(&str) -> bool,
    ) -> Self {
        Self {
            id,
            title,
            regex: Regex::new(pattern).expect("built-in regex must compile"),
            base_risk,
            validator: Some(validator),
        }
    }
}

fn roc_letter_val(c: char) -> Option<u32> {
    match c {
        'A' => Some(10),
        'B' => Some(11),
        'C' => Some(12),
        'D' => Some(13),
        'E' => Some(14),
        'F' => Some(15),
        'G' => Some(16),
        'H' => Some(17),
        'I' => Some(34),
        'J' => Some(18),
        'K' => Some(19),
        'L' => Some(20),
        'M' => Some(21),
        'N' => Some(22),
        'O' => Some(35),
        'P' => Some(23),
        'Q' => Some(24),
        'R' => Some(25),
        'S' => Some(26),
        'T' => Some(27),
        'U' => Some(28),
        'V' => Some(29),
        'W' => Some(32),
        'X' => Some(30),
        'Y' => Some(31),
        'Z' => Some(33),
        _ => None,
    }
}

pub fn is_valid_taiwan_national_id(id: &str) -> bool {
    let id = id.trim().to_ascii_uppercase();
    if id.len() != 10 {
        return false;
    }
    let mut chars = id.chars();
    let first_char = chars.next().unwrap();
    let letter_val = match roc_letter_val(first_char) {
        Some(v) => v,
        None => return false,
    };

    let d1 = letter_val / 10;
    let d2 = letter_val % 10;

    let mut sum = d1 * 1 + d2 * 9;

    let weights = [8, 7, 6, 5, 4, 3, 2, 1, 1];
    for (i, c) in chars.enumerate() {
        if let Some(digit) = c.to_digit(10) {
            sum += digit * weights[i];
        } else {
            return false;
        }
    }

    sum % 10 == 0
}

pub fn is_valid_taiwan_arc_ui(id: &str) -> bool {
    let id = id.trim().to_ascii_uppercase();
    if id.len() != 10 {
        return false;
    }
    let chars: Vec<char> = id.chars().collect();

    let first_char_val = match roc_letter_val(chars[0]) {
        Some(v) => v,
        None => return false,
    };
    let d1 = first_char_val / 10;
    let d2 = first_char_val % 10;

    if chars[1].is_ascii_digit() {
        // New ARC/UI format: e.g., F801234564
        let mut sum = d1 * 1 + d2 * 9;
        let weights = [8, 7, 6, 5, 4, 3, 2, 1, 1];
        for i in 0..9 {
            if let Some(digit) = chars[i + 1].to_digit(10) {
                sum += digit * weights[i];
            } else {
                return false;
            }
        }
        sum % 10 == 0
    } else {
        // Old ARC format: e.g., FA12345670
        let second_char_val = match roc_letter_val(chars[1]) {
            Some(v) => v,
            None => return false,
        };
        let d4 = second_char_val % 10;

        let mut sum = d1 * 1 + d2 * 9 + d4 * 8;
        let weights = [7, 6, 5, 4, 3, 2, 1, 1];
        for i in 0..8 {
            if let Some(digit) = chars[i + 2].to_digit(10) {
                sum += digit * weights[i];
            } else {
                return false;
            }
        }
        sum % 10 == 0
    }
}

pub fn is_valid_taiwan_einvoice_barcode(barcode: &str) -> bool {
    let barcode = barcode.trim();
    if !barcode.starts_with('/') || barcode.chars().count() != 8 {
        return false;
    }
    let content = &barcode[1..];

    // 1. Filter out IP address segments (contains dots but no letters, e.g. /169.254, /127.0.0)
    let has_dot = content.contains('.');
    let has_letter = content.chars().any(|c| c.is_ascii_alphabetic());
    if has_dot && !has_letter {
        return false;
    }

    // 2. Filter out command line flags (consisting entirely of letters, e.g. /COPYALL)
    let is_all_letters = content.chars().all(|c| c.is_ascii_alphabetic());
    if is_all_letters {
        return false;
    }

    true
}

pub fn is_valid_azure_sas_uri(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();

    // 1. Must be an Azure Blob / Azure Storage domain.
    //    Google Forms, GitHub, etc. may also carry sv= / sig= params — ignore them.
    let is_azure_domain = lower.contains(".blob.core.windows.net")
        || lower.contains(".file.core.windows.net")
        || lower.contains(".queue.core.windows.net")
        || lower.contains(".table.core.windows.net")
        || lower.contains(".dfs.core.windows.net");
    if !is_azure_domain {
        return false;
    }

    // 2. Reject if the hostname contains placeholder tokens like YOUR_ACCOUNT, {account}, etc.
    let hostname = lower.split('/').nth(2).unwrap_or("");
    if hostname.contains("your_account")
        || hostname.contains("your-account")
        || hostname.contains("youraccount")
        || hostname.contains("{account}")
        || hostname.contains("<account>")
        || hostname.contains("[account]")
        || hostname.starts_with("account.")
    {
        return false;
    }

    // 3. The query string must exist and `sig=` must be present.
    let query = match lower.split_once('?') {
        Some((_, q)) => q,
        None => return false,
    };

    let has_sig = query.split('&').any(|p| p.starts_with("sig="));
    if !has_sig {
        // No sig= at all → not a real SAS URI (just a URL with sv= or sp=)
        return false;
    }

    // 4. sig= value must not be a placeholder ("...", "xxx", template variables, etc.)
    for part in query.split('&') {
        if let Some(val) = part.strip_prefix("sig=") {
            let val = val.trim();
            // Ellipsis-only or empty → placeholder
            if val.is_empty() || val == "..." || val == ".." || val == "." {
                return false;
            }
            // Looks like a template variable: {sig}, <sig>, [sig]
            if (val.starts_with('{') && val.ends_with('}'))
                || (val.starts_with('<') && val.ends_with('>'))
                || (val.starts_with('[') && val.ends_with(']'))
            {
                return false;
            }
            // Contains "your" prefix → placeholder
            if val.to_ascii_lowercase().starts_with("your") {
                return false;
            }
            // Real SAS sig is a Base64-like string, typically 40+ chars
            // If shorter than 20 chars after URL-decoding estimate, treat as placeholder
            let decoded_estimate = val
                .replace("%2b", "+")
                .replace("%2f", "/")
                .replace("%3d", "=");
            if decoded_estimate.len() < 20 {
                return false;
            }
        }
    }

    // 5. The URL must not be split across multiple lines.
    //    A real SAS URI should be on a single line (no whitespace in the URL itself).
    if uri.contains('\n') || uri.contains('\r') {
        return false;
    }

    true
}

pub static SECRET_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    vec![
        SecretPattern::new(
            "openai_api_key",
            "OpenAI API Key",
            r"\b(?P<secret>sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b",
            90,
        ),
        SecretPattern::new(
            "anthropic_api_key",
            "Anthropic API Key",
            r"\b(?P<secret>sk-ant-api\d{2}-[A-Za-z0-9_-]{40,})\b",
            90,
        ),
        SecretPattern::new(
            "xai_api_key",
            "xAI API Key",
            r"\b(?P<secret>xai-[A-Za-z0-9_-]{20,})\b",
            85,
        ),
        SecretPattern::new(
            "groq_api_key",
            "Groq API Key",
            r"\b(?P<secret>gsk_[A-Za-z0-9]{32,})\b",
            85,
        ),
        SecretPattern::new(
            "openrouter_api_key",
            "OpenRouter API Key",
            r"\b(?P<secret>sk-or-v1-[A-Za-z0-9_-]{32,})\b",
            85,
        ),
        SecretPattern::new(
            "replicate_api_token",
            "Replicate API Token",
            r"\b(?P<secret>r8_[A-Za-z0-9]{32,})\b",
            85,
        ),
        SecretPattern::new(
            "huggingface_token",
            "Hugging Face Token",
            r"\b(?P<secret>hf_[A-Za-z0-9]{30,})\b",
            80,
        ),
        SecretPattern::new(
            "google_api_key",
            "Google API Key",
            r"\b(?P<secret>AIza[0-9A-Za-z\-_]{35})\b",
            85,
        ),
        SecretPattern::new(
            "github_token",
            "GitHub Token",
            r"\b(?P<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
            95,
        ),
        SecretPattern::new(
            "stripe_key",
            "Stripe Secret or Restricted Key",
            r"\b(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|sk_org_[A-Za-z0-9]{16,})\b",
            95,
        ),
        SecretPattern::new(
            "slack_token",
            "Slack Token",
            r"\b(?P<secret>(?:xoxb|xoxp|xapp|xwfp)-[A-Za-z0-9-]{10,})\b",
            90,
        ),
        SecretPattern::new(
            "sendgrid_key",
            "SendGrid API Key",
            r"\b(?P<secret>SG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
            90,
        ),
        SecretPattern::new(
            "sentry_auth_token",
            "Sentry Auth Token",
            r"\b(?P<secret>sntrys_[A-Za-z0-9_-]{20,})\b",
            85,
        ),
        SecretPattern::new(
            "docker_pat",
            "Docker Hub PAT",
            r"\b(?P<secret>dckr_pat_[A-Za-z0-9_-]{20,})\b",
            90,
        ),
        SecretPattern::new(
            "aws_access_key_id",
            "AWS Access Key ID",
            r"\b(?P<secret>(?:AKIA|ASIA)[A-Z0-9]{16})\b",
            85,
        ),
        SecretPattern::new(
            "aws_secret_access_key",
            "AWS Secret Access Key",
            r#"(?i)(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|secret_access_key)\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9/+=]{40})[\"']?"#,
            95,
        ),
        SecretPattern::new(
            "azure_storage_connection_string",
            "Azure Storage Connection String",
            r"(?i)(?P<secret>DefaultEndpointsProtocol\s*=\s*(?:https|http)\s*;[^\n]{0,200}?AccountName\s*=\s*[A-Za-z0-9-]{3,24}\s*;[^\n]{0,200}?AccountKey\s*=\s*[A-Za-z0-9+/]{86}==)",
            95,
        ),
        SecretPattern::new(
            "azure_storage_key_generic",
            "Azure Storage AccountKey",
            r"(?i)AccountKey\s*=\s*(?P<secret>[A-Za-z0-9+/]{86}==)",
            90,
        ),
        SecretPattern::new_with_validator(
            "azure_sas_uri",
            "Azure SAS URI",
            r#"(?i)\b(?P<secret>https?://[^\s"'`<>]+\.(?:blob|file|queue|table|dfs)\.core\.windows\.net/[^\s"'`<>]*\?[^\s"'`<>]*(?:sv|se|sp|sig)=[^\s"'`<>]+)"#,
            90,
            is_valid_azure_sas_uri,
        ),
        SecretPattern::new(
            "framework_app_secret_context",
            "Framework App Secret",
            r#"(?i)(?:\b(?:DJANGO_SECRET_KEY|FLASK_SECRET_KEY|SECRET_KEY|SECRET_KEY_BASE|APP_KEY|JWT_SECRET|SESSION_SECRET|AUTH_SECRET|NEXTAUTH_SECRET|NUXT_SESSION_PASSWORD|RAILS_MASTER_KEY|TOKEN_KEY|SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_[A-Z0-9_]+_CLIENT_SECRET)\b|secret_key_base)\s*[:=]\s*[\"']?(?P<secret>(?:base64:)?[A-Za-z0-9][A-Za-z0-9/_+=.-]{15,127})[\"']?"#,
            80,
        ),
        SecretPattern::new(
            "twilio_account_sid",
            "Twilio Account SID",
            r"\b(?P<secret>AC[0-9a-fA-F]{32})\b",
            70,
        ),
        SecretPattern::new(
            "twilio_api_key_sid",
            "Twilio API Key SID",
            r"\b(?P<secret>SK[0-9a-fA-F]{32})\b",
            70,
        ),
        SecretPattern::new(
            "twilio_auth_token",
            "Twilio Auth Token",
            r#"(?i)(?:TWILIO_AUTH_TOKEN|auth_token)\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9]{16,64})[\"']?"#,
            80,
        ),
        SecretPattern::new(
            "datadog_key_context",
            "Datadog API or App Key",
            r#"(?i)(?:DD_API_KEY|DD_APP_KEY|DD_APPLICATION_KEY)\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9]{20,64})[\"']?"#,
            80,
        ),
        SecretPattern::new(
            "heroku_api_key_context",
            "Heroku API Key",
            r#"(?i)HEROKU_API_KEY\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9-]{20,})[\"']?"#,
            85,
        ),
        SecretPattern::new_with_validator(
            "database_connection_string",
            "Database Connection String",
            r#"(?i)(?P<secret>(?:[A-Za-z][A-Za-z0-9 _.-]{0,40}\s*=\s*[^;"'\r\n]*\s*;){1,20}\s*\b(?:Password|Pwd)\b\s*=\s*[^;"'\r\n]{6,}(?:\s*;\s*[A-Za-z][A-Za-z0-9 _.-]{0,40}\s*=\s*[^;"'\r\n]*){0,20}|\b(?:Password|Pwd)\b\s*=\s*[^;"'\r\n]{6,}(?:\s*;\s*[A-Za-z][A-Za-z0-9 _.-]{0,40}\s*=\s*[^;"'\r\n]*){1,20})"#,
            80,
            is_valid_database_connection_string,
        ),
        SecretPattern::new(
            "postgres_uri",
            "PostgreSQL URI",
            r#"(?i)\b(?P<secret>postgres(?:ql)?://[^\s"'`<>]+)\b"#,
            80,
        ),
        SecretPattern::new(
            "mongodb_uri",
            "MongoDB URI",
            r#"(?i)\b(?P<secret>mongodb(?:\+srv)?://[^\s"'`<>]+)\b"#,
            80,
        ),
        SecretPattern::new(
            "redis_uri",
            "Redis URI",
            r#"(?i)\b(?P<secret>rediss?://[^\s"'`<>]+)\b"#,
            80,
        ),
        SecretPattern::new(
            "jwt",
            "JWT",
            r"\b(?P<secret>eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
            75,
        ),
        SecretPattern::new(
            "private_key_pem",
            "PEM Private Key",
            r#"(?P<secret>-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----(?:[^\r\n\"']*?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----(?:\\r\\n|\\n|\\r)?|[^\r\n\"']*))"#,
            100,
        ),
        SecretPattern::new(
            "certificate_pem",
            "PEM Certificate",
            r"(?P<secret>-----BEGIN CERTIFICATE-----)",
            25,
        ),
        SecretPattern::new(
            "ssh_public_key",
            "SSH Public Key",
            r"(?i)\b(?P<secret>ssh-(?:rsa|ed25519|ecdsa-[a-z0-9-]+)\s+[A-Za-z0-9+/=]{20,}(?:\s+[^\n\r]+)?)",
            20,
        ),
        SecretPattern::new(
            "gcp_service_account_json",
            "GCP Service Account JSON",
            r#"(?s)"type"\s*:\s*"service_account".*?"private_key_id"\s*:\s*"(?P<secret>[^"]+)""#,
            95,
        ),
        SecretPattern::new(
            "google_oauth_client_secret",
            "Google OAuth Client Secret",
            r#""client_secret"\s*:\s*"(?P<secret>[^"]{8,})""#,
            80,
        ),
        SecretPattern::new_with_validator(
            "taiwan_national_id",
            "Taiwan National ID",
            r"\b(?P<secret>[A-Z][12]\d{8})\b",
            85,
            is_valid_taiwan_national_id,
        ),
        SecretPattern::new_with_validator(
            "taiwan_arc_ui",
            "Taiwan UI/ARC/APRC Number",
            r"\b(?P<secret>[A-Z][89A-D]\d{8})\b",
            85,
            is_valid_taiwan_arc_ui,
        ),
        SecretPattern::new(
            "taiwan_mobile",
            "Taiwan Mobile Phone Number",
            r"(?:^|[^0-9])(?P<secret>(?:\+?886[-\s]?|0)9(?:[-\s]?[0-9]){8})\b",
            50,
        ),
        SecretPattern::new_with_validator(
            "taiwan_einvoice_barcode",
            "Taiwan E-Invoice Mobile Barcode",
            r#"(?:^|[^A-Za-z0-9])(?P<secret>/[A-Z0-9.+\-]{7})(?:\b|[^A-Z0-9.+\-])"#,
            20,
            is_valid_taiwan_einvoice_barcode,
        ),
        SecretPattern::new(
            "taiwan_citizen_certificate",
            "Taiwan Citizen Digital Certificate Number",
            r"\b(?P<secret>[A-Z]{2}\d{14})\b",
            30,
        ),
    ]
});

pub static WEAK_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(?:x+|a+|0+|1+|abc(?:def)?|example|sample|dummy|placeholder|change_me|replace_me|your[_-]?(?:api[_-]?)?key|localhost|127\.0\.0\.1|contoso|northwind|sandbox|<account-key>|<your_api_key_here>|<auth_token>)$")
        .expect("weak secret regex")
});

pub fn is_likely_placeholder(secret: &str) -> bool {
    let trimmed = secret.trim().trim_matches(['\"', '\'', '`']);
    WEAK_SECRET_RE.is_match(trimmed)
        || has_repeated_single_char_body(trimmed)
        || is_taiwan_placeholder(trimmed)
        || contains_placeholder_password(trimmed)
}

pub fn is_weak_password_val(val: &str) -> bool {
    let val = val.trim().to_ascii_lowercase();
    val.is_empty()
        || val == "password"
        || val == "your-password"
        || val == "your_password"
        || val == "yourpassword"
        || val == "yourstrong@passw0rd"
        || val == "mypassword"
        || val == "secret"
        || val == "dbpassword"
        || val == "change_me"
        || val == "changeme"
        || val == "placeholder"
        || val == "admin"
        || val == "sa"
        || val == "root"
        || val.contains("example")
        || val.contains("dummy")
        || val.contains("sample")
        || val.starts_with('<') && val.ends_with('>')
        || val.starts_with('[') && val.ends_with(']')
        || val.starts_with('{') && val.ends_with('}')
}

pub fn contains_placeholder_password(conn_str: &str) -> bool {
    let lower_conn = conn_str.to_ascii_lowercase();
    if let Some(pos) = lower_conn.find("password") {
        let suffix = &lower_conn[pos + "password".len()..];
        let trimmed_suffix = suffix.trim_start();
        if trimmed_suffix.starts_with('=') {
            let val_part = &trimmed_suffix[1..];
            let val = val_part
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(['\"', '\'', '`']);
            if is_weak_password_val(val) {
                return true;
            }
        }
    }
    if let Some(pos) = lower_conn.find("pwd") {
        let suffix = &lower_conn[pos + "pwd".len()..];
        let trimmed_suffix = suffix.trim_start();
        if trimmed_suffix.starts_with('=') {
            let val_part = &trimmed_suffix[1..];
            let val = val_part
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(['\"', '\'', '`']);
            if is_weak_password_val(val) {
                return true;
            }
        }
    }
    false
}

pub fn is_valid_database_connection_string(conn_str: &str) -> bool {
    let lower = conn_str.to_ascii_lowercase();
    let mut has_db_keyword = false;
    let mut has_invalid_code_patterns = false;

    for part in lower.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(eq_idx) = trimmed.find('=') {
            let key = trimmed[..eq_idx].trim();
            let val = trimmed[eq_idx + 1..].trim();

            if key.starts_with("var ")
                || key.starts_with("string ")
                || key.starts_with("let ")
                || key.starts_with("const ")
                || key.starts_with("public ")
                || key.starts_with("private ")
                || key.contains('(')
                || key.contains(')')
            {
                has_invalid_code_patterns = true;
                break;
            }

            if val.contains("await ")
                || val.contains("getnewpassword")
                || val.contains("hashpassword")
            {
                has_invalid_code_patterns = true;
                break;
            }

            match key {
                "server" | "host" | "data source" | "datasource" | "address" | "addr" | "port"
                | "database" | "initial catalog" | "db" | "user id" | "userid" | "uid" | "user"
                | "username" | "password" | "pwd" => {
                    has_db_keyword = true;
                }
                _ => {}
            }
        }
    }

    has_db_keyword && !has_invalid_code_patterns
}

pub fn is_taiwan_placeholder(secret: &str) -> bool {
    let normalized: String = secret
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '/')
        .collect();

    // Check Mobile placeholders
    if normalized.starts_with("09") || normalized.starts_with("8869") {
        let digits: String = normalized.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 10 {
            if digits.contains("0912345678") || digits.contains("0987654321") {
                return true;
            }
            let last_8 = &digits[digits.len() - 8..];
            if last_8.chars().all(|c| c == last_8.chars().next().unwrap()) {
                return true;
            }
        }
    }

    // Check E-Invoice barcode placeholders
    if normalized.starts_with('/') && normalized.len() == 8 {
        let body = &normalized[1..];
        if body == "1234567" || body == "7654321" || body.to_ascii_lowercase() == "abc1234" {
            return true;
        }
        if body.chars().all(|c| c == body.chars().next().unwrap()) {
            return true;
        }
    }

    false
}

fn has_repeated_single_char_body(secret: &str) -> bool {
    let normalized: Vec<u8> = secret
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b.to_ascii_lowercase())
        .collect();

    if normalized.len() < 17 {
        return false;
    }

    (1..normalized.len()).any(|start| {
        let body = &normalized[start..];
        body.len() >= 16 && body.iter().all(|b| *b == body[0])
    })
}
