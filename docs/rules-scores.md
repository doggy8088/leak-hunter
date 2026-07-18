# 掃描規則與風險分數對照表

本文件詳細列出 `leak-hunter` 中所有內建的密鑰與個人資料（含台灣 PDPA 第一階段）掃描規則之基礎風險分數（Base Risk），以及風險評分模型中的加減分與調降規則。

---

## 1. 風險評級定義

風險分數範圍為 `0` 至 `100` 分，其對應的風險評級如下：

*   **極高風險 (Critical)**：90–100 分
*   **高風險 (High)**：75–89 分
*   **中風險 (Medium)**：40–74 分
*   **低風險 (Low)**：0–39 分

---

## 2. 全域掃描規則與基礎分數

以下為 `leak-hunter` 支援的所有掃描規則及其基礎分數（Base Risk）：

| 規則代號 (Pattern ID) | 掃描項目名稱 (Title) | 基礎分數 | 預設評級 | 備註說明 / 格式特徵 |
| :--- | :--- | :---: | :---: | :--- |
| `private_key_pem` | PEM Private Key | **100** | Critical | PEM 格式私鑰首尾特徵，極高敏感性 |
| `github_token` | GitHub Token | **95** | Critical | `ghp_`, `gho_` 等前綴，或 `github_pat_` |
| `gitlab_token` | GitLab Token | **95** | Critical | `glpat-` 開頭之個人存取權杖 |
| `stripe_key` | Stripe Secret/Restricted Key | **95** | Critical | `sk_live_`, `rk_live_` 等前綴 |
| `aws_secret_access_key` | AWS Secret Access Key | **95** | Critical | 需搭配 `aws_secret_access_key` 等變數名偵測 |
| `azure_storage_connection_string`| Azure Storage Connection String| **95** | Critical | 包含 `AccountName` 與 `AccountKey` 的完整連線字串 |
| `gcp_service_account_json` | GCP Service Account JSON | **95** | Critical | GCP 服務帳戶私鑰金鑰 JSON 結構 |
| `hashicorp_vault_token` | HashiCorp Vault Token | **95** | Critical | `hvs.`, `hvb.`, `hvr.` 開頭之 Vault Token |
| `braintree_access_token` | Braintree Access Token | **95** | Critical | `access_token$production$...` 或 sandbox 形式 |
| `openai_api_key` | OpenAI API Key | **90** | Critical | `sk-` 或 `sk-proj-` 開頭之 API 金鑰 |
| `anthropic_api_key` | Anthropic API Key | **90** | Critical | `sk-ant-api` 開頭之 API 金鑰 |
| `slack_token` | Slack Token | **90** | Critical | `xoxb-`, `xoxp-`, `xapp-` 等 Token |
| `slack_webhook_url` | Slack Webhook URL | **90** | Critical | `https://hooks.slack.com/services/...` Webhook URL |
| `discord_webhook_url` | Discord Webhook URL | **90** | Critical | Discord `/api/webhooks/...` URL |
| `sendgrid_key` | SendGrid API Key | **90** | Critical | `SG.` 開頭之金鑰 |
| `docker_pat` | Docker Hub PAT | **90** | Critical | `dckr_pat_` 開頭之個人存取權杖 |
| `npm_token` | npm Access Token | **90** | Critical | `npm_` 開頭之 access token |
| `pypi_api_token` | PyPI API Token | **90** | Critical | `pypi-` 開頭之 API Token |
| `digitalocean_token` | DigitalOcean Token | **90** | Critical | `dop_v1_` 等 DigitalOcean Token |
| `doppler_token` | Doppler Token | **90** | Critical | `dp.pt.`, `dp.st.`, `dp.ct.` 開頭之 Token |
| `shopify_access_token` | Shopify Access Token | **90** | Critical | `shpat_`, `shppa_` 等 Shopify Token |
| `square_access_token` | Square Access Token | **90** | Critical | `sq0atp-` / `sq0atb-` 開頭之 Square Token |
| `square_application_secret` | Square Application Secret | **90** | Critical | `sq0csp-` 開頭之 Square application secret |
| `airtable_pat` | Airtable Personal Access Token | **90** | Critical | Airtable `pat...` 個人存取權杖 |
| `mailchimp_api_key` | Mailchimp API Key | **90** | Critical | 32 碼 hex 加 datacenter suffix，例如 `-us20` |
| `cloudflare_api_token_context` | Cloudflare API Token | **90** | Critical | 需搭配 `CLOUDFLARE_API_TOKEN` / `CF_API_TOKEN` 變數偵測 |
| `vault_legacy_token_context` | Vault Legacy Token | **90** | Critical | 需搭配 `VAULT_TOKEN` 變數偵測 legacy `s.` Token |
| `mailgun_api_key_context` | Mailgun API Key | **90** | Critical | 需搭配 `MAILGUN_API_KEY` 變數偵測 |
| `microsoft_teams_webhook_url` | Microsoft Teams Webhook URL | **90** | Critical | `webhook.office.com` IncomingWebhook URL |
| `azure_storage_key_generic` | Azure Storage AccountKey | **90** | Critical | 獨立的 Azure 帳戶金鑰特徵 |
| `azure_sas_uri` | Azure SAS URI | **90** | Critical | 包含 SAS 簽章的金鑰網址 |
| `xai_api_key` | xAI API Key | **85** | High | `xai-` 開頭之 API 金鑰 |
| `groq_api_key` | Groq API Key | **85** | High | `gsk_` 開頭之金鑰 |
| `openrouter_api_key` | OpenRouter API Key | **85** | High | `sk-or-v1-` 開頭之金鑰 |
| `replicate_api_token` | Replicate API Token | **85** | High | `r8_` 開頭之 Token |
| `google_api_key` | Google API Key | **85** | High | `AIza` 開頭之 Google API 密鑰 |
| `sentry_auth_token` | Sentry Auth Token | **85** | High | `sntrys_` 開頭之 Sentry 授權權杖 |
| `aws_access_key_id` | AWS Access Key ID | **85** | High | `AKIA` 或 `ASIA` 開頭之 16 碼識別碼 |
| `telegram_bot_token` | Telegram Bot Token | **85** | High | Telegram Bot token 數字 ID 加冒號與 token body |
| `paypal_client_secret_context` | PayPal Client Secret | **85** | High | 需搭配 `PAYPAL_SECRET` / `PAYPAL_CLIENT_SECRET` 變數偵測 |
| `notion_token_context` | Notion API Token | **85** | High | 需搭配 `NOTION_*` 變數偵測 `secret_` / `ntn_` Token |
| `postmark_api_token_context` | Postmark API Token | **85** | High | 需搭配 `POSTMARK_*TOKEN` 變數偵測 UUID token |
| `teams_logic_webhook_context` | Microsoft Teams Logic App Webhook URL | **85** | High | 需搭配 Teams 變數名偵測 `logic.azure.com` 且含 `sig=` 的 URL |
| `heroku_api_key_context` | Heroku API Key | **85** | High | 需搭配 `HEROKU_API_KEY` 變數偵測 |
| `datadog_key_context` | Datadog API or App Key | **80** | High | 需搭配 `DD_API_KEY`, `DD_APP_KEY` 或 `DD_APPLICATION_KEY` 變數偵測 |
| `taiwan_national_id` | 中華民國國民身分證統一編號 | **85** | High | **台灣個資**：首碼英文字母 + 9 碼數字，**含 checksum 校驗** |
| `taiwan_arc_ui` | 中華民國居留證/統一證號 | **85** | High | **台灣個資**：新舊版統一證號，**含 checksum 校驗** |
| `huggingface_token` | Hugging Face Token | **80** | High | `hf_` 開頭之 Token |
| `framework_app_secret_context` | Framework App Secret | **80** | High | 常見開發框架金鑰（如 Django, Rails, Laravel 等） |
| `twilio_auth_token` | Twilio Auth Token | **80** | High | Twilio 授權 Token |
| `database_connection_string` | Database Connection String | **80** | High | 含 `Password` 或 `Pwd` 欄位之資料庫連線字串 |
| `postgres_uri` | PostgreSQL URI | **80** | High | `postgres://` 或 `postgresql://` 格式 |
| `mongodb_uri` | MongoDB URI | **80** | High | `mongodb://` 或 `mongodb+srv://` 格式 |
| `redis_uri` | Redis URI | **80** | High | `redis://` 或 `rediss://` 格式 |
| `google_oauth_client_secret` | Google OAuth Client Secret | **80** | High | GCP OAuth 客戶端密鑰特徵 |
| `snyk_token_context` | Snyk API Token | **80** | High | 需搭配 `SNYK_TOKEN` / `SNYK_API_TOKEN` 變數偵測 UUID token |
| `netlify_auth_token_context` | Netlify Auth Token | **80** | High | 需搭配 `NETLIFY_AUTH_TOKEN` 變數偵測 |
| `jwt` | JWT (JSON Web Token) | **75** | High | 以 `eyJ` 開頭的 JWT 連續字串 |
| `sonar_token_context` | Sonar Token | **75** | High | 需搭配 `SONAR_TOKEN` 變數偵測 40 碼 hex token |
| `twilio_account_sid` | Twilio Account SID | **70** | Medium | `AC` 開頭的 32 碼識別碼 |
| `twilio_api_key_sid` | Twilio API Key SID | **70** | Medium | `SK` 開頭的 32 碼識別碼 |
| `generic_password_context` | Generic Password Field | **65** | Medium | 完整密碼標籤後接同一行高隨機性 ASCII 候選值 |
| `taiwan_mobile` | 台灣手機號碼 | **50** | Medium | **台灣個資**：`09` 或 `+8869` 開頭共 10 碼（支援 `-` 或空格） |
| `taiwan_citizen_certificate` | 台灣自然人憑證號碼 | **30** | Low | **台灣個資**：2 碼大寫英文字母 + 14 碼數字；搭配自然人憑證上下文時會提高風險 |
| `taiwan_einvoice_barcode` | 台灣電子發票手機條碼載具 | **20** | Low | **台灣個資**：`/` 開頭共 8 碼（符合載具字元特徵），本身不具機密性，風險極低 |
| `certificate_pem` | PEM Certificate | **25** | Low | PEM 格式憑證公開部分 |
| `ssh_public_key` | SSH Public Key | **20** | Low | SSH 公開金鑰 |

---

## 3. 風險分數微調規則 (Context Adjustments)

在掃描到潛在密鑰後，系統會結合檔案位置與周圍上下文對基礎分數進行增減：

### A. 檔案路徑與命名加成
*   **環境變數檔案 (Env Files)**：
    *   若檔案路徑後綴為 `.env` 或包含 `.env.`，分數 **`+8`**。
    *   精確檔名為 `.env.example` 時，改為分數 **`-25`**，且不套用前述 `+8` 加成。
*   **配置與工作流路徑 (Config/Workflow)**：
    *   若檔案路徑中包含 `config`、`settings` 或 `workflow`，分數 **`+5`**。
*   **說明文件路徑 (Docs/Readme) 的扣分**：
    *   若檔案路徑中包含 `readme` 或 `docs/`，分數 **`-25`**。

### B. 上下文內容調整
*   **低熵值扣分 (Low Entropy)**：
    *   若密鑰長度小於 24 碼，且其香農熵（Shannon Entropy）小於 `3.0`，分數 **`-20`**。
*   **公開性/證書扣分 (Public/Certificate)**：
    *   若上下文 150 字元內包含 `public key` 或 `certificate` 關鍵字，分數 **`-10`**。

### C. 特定規則專屬調整
*   **一般密碼欄位規則**：
    *   `generic_password_context` 只接受完整的 `password`、`passwd` 或 `pwd` 標籤，並要求候選值位於同一行。
    *   候選值長度須為 8 至 128 個 ASCII 字元、至少包含兩種字元類別、6 個不同字元，且香農熵大於等於 `3.0`。
    *   URL、程式碼成員存取、帶參數或不帶參數的函式與方法呼叫，以及明顯識別字不會產生 finding；此判斷不依賴副檔名。
    *   基礎分數為 `65`；即使位於 `README` 或 `docs/` 路徑並扣除 25 分，仍為 `40` 分，可在預設門檻顯示。
*   **Google API Key 於 Firebase 的扣分**：
    *   當規則為 `google_api_key`，且檔案路徑包含 `firebase`、`google-services.json`、`googleservice-info.plist` 或內容含 `firebaseconfig` 時，因通常為公開設定，分數 **`-55`**。
*   **AWS Access Key ID 存在 Secret Key 的加成**：
    *   當規則為 `aws_access_key_id`，且同一檔案中亦偵測到 `secret_access_key` 關鍵字時，分數 **`+10`**。
*   **Compose PostgreSQL 環境變數插值抑制**：
    *   在精確檔名 `compose.yaml` 中，若 PostgreSQL URI 的使用者名稱、密碼與資料庫名稱皆為純 `${VAR}` 插值，則不產生 finding；若任一帳密為字面值，仍照常回報。

### D. 台灣 PDPA 個資規則專屬加成
針對以 `taiwan_` 開頭的台灣個資規則，若匹配點周圍 **150 字元窗格**內包含特定個資關聯關鍵字時，分數 **`+15`**（分數上限調整至 100 分）：
*   **`taiwan_national_id`** 關聯詞：`身分證`、`身分證字號`、`national id`、`identity card`、`國民身分證`、`身分證統一編號`、`id`（獨立英文單字）。
*   **`taiwan_arc_ui`** 關聯詞：`統一證號`、`居留證`、`arc`、`aprc`（獨立英文單字）、`resident certificate`。
*   **`taiwan_mobile`** 關聯詞：`手機`、`電話`、`mobile`、`cellphone`、`phone`。
*   **`taiwan_einvoice_barcode`** 關聯詞：`載具`、`手機條碼`、`條碼`、`barcode`、`einvoice`、`e-invoice`。
*   **`taiwan_citizen_certificate`** 關聯詞：`自然人憑證`、`憑證`、`citizen certificate`、`digital certificate`。

---

## 4. 佔位字元與測試範例評級調降 (Placeholders)

為避免開發過程中的假資料或註解範例干擾主要報告，但同時確保其能被分析出來，系統針對符合以下條件的檢出，**直接將其風險分數設為 `30` 分（Low 風險）**：

1.  **台灣個資假資料 (`is_taiwan_placeholder`)**：
    *   **手機號碼**：含有 `0912345678`、`0987654321`，或後 8 碼全部相同的號碼（如 `0900000000`）。
    *   **手機條碼載具**：含有 `/1234567`、`/7654321`、`/ABC1234`，或斜線後 7 碼全部相同的條碼（如 `/XXXXXXX`）。
2.  **一般系統佔位金鑰 (`is_likely_placeholder`)**：
    *   符合常見金鑰佔位模式（如 `sk-xxxxxxxxxxxxxxxxxxxxxxxx`、`example`、`dummy`、`placeholder`、`your_api_key_here` 等）。
    *   具有大於等於 16 碼連續相同字元的主體金鑰。
3.  **一般密碼欄位佔位值**：
    *   弱密碼名稱、環境變數引用與模板引用會保留為 `30` 分 Low finding，不會出現在預設 `--min-risk 40` 報告中。
4.  **說明文件範例**：
    *   若檔案路徑中含有 `readme`、`docs/`、`documentation` 或 `guide`。
    *   且檢出的密鑰值中包含 `example`、`sample` 或 `dummy`。

---

## 5. 一般密碼欄位遮罩

`generic_password_context` 在預設 redaction 模式下固定輸出 `[REDACTED]`，不保留候選值的前後片段。報告仍會保留不可逆的短雜湊與 entropy，供重複 finding 比對及人工分流。
