use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub id: &'static str,
    pub title: &'static str,
    pub regex: Regex,
    pub base_risk: u8,
}

impl SecretPattern {
    fn new(id: &'static str, title: &'static str, pattern: &'static str, base_risk: u8) -> Self {
        Self {
            id,
            title,
            regex: Regex::new(pattern).expect("built-in regex must compile"),
            base_risk,
        }
    }
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
        SecretPattern::new(
            "azure_sas_uri",
            "Azure SAS URI",
            r#"(?i)\b(?P<secret>https?://[^\s"'`<>]+\?[^\s"'`<>]*(?:sv|se|sp|sig)=[^\s"'`<>]+)"#,
            90,
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
        SecretPattern::new(
            "database_connection_string",
            "Database Connection String",
            r#"(?i)(?P<secret>(?:[A-Za-z][A-Za-z0-9 _.-]{0,40}\s*=\s*[^;"'\r\n]*\s*;){1,20}\s*(?:Password|Pwd)\s*=\s*[^;"'\r\n]{6,}(?:\s*;\s*[A-Za-z][A-Za-z0-9 _.-]{0,40}\s*=\s*[^;"'\r\n]*){0,20}|(?:Password|Pwd)\s*=\s*[^;"'\r\n]{6,}(?:\s*;\s*[A-Za-z][A-Za-z0-9 _.-]{0,40}\s*=\s*[^;"'\r\n]*){1,20})"#,
            80,
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
    ]
});

pub static WEAK_SECRET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(?:x+|a+|0+|1+|abc(?:def)?|example|sample|dummy|placeholder|change_me|replace_me|your[_-]?(?:api[_-]?)?key|localhost|127\.0\.0\.1|contoso|northwind|sandbox|<account-key>|<your_api_key_here>|<auth_token>)$")
        .expect("weak secret regex")
});

pub fn is_likely_placeholder(secret: &str) -> bool {
    let trimmed = secret.trim().trim_matches(['\"', '\'', '`']);
    WEAK_SECRET_RE.is_match(trimmed) || has_repeated_single_char_body(trimmed)
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
