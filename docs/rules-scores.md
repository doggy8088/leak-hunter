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
| `stripe_key` | Stripe Secret/Restricted Key | **95** | Critical | `sk_live_`, `rk_live_` 等前綴 |
| `aws_secret_access_key` | AWS Secret Access Key | **95** | Critical | 需搭配 `aws_secret_access_key` 等變數名偵測 |
| `azure_storage_connection_string`| Azure Storage Connection String| **95** | Critical | 包含 `AccountName` 與 `AccountKey` 的完整連線字串 |
| `gcp_service_account_json` | GCP Service Account JSON | **95** | Critical | GCP 服務帳戶私鑰金鑰 JSON 結構 |
| `openai_api_key` | OpenAI API Key | **90** | Critical | `sk-` 或 `sk-proj-` 開頭之 API 金鑰 |
| `anthropic_api_key` | Anthropic API Key | **90** | Critical | `sk-ant-api` 開頭之 API 金鑰 |
| `slack_token` | Slack Token | **90** | Critical | `xoxb-`, `xoxp-`, `xapp-` 等 Token |
| `sendgrid_key` | SendGrid API Key | **90** | Critical | `SG.` 開頭之金鑰 |
| `docker_pat` | Docker Hub PAT | **90** | Critical | `dckr_pat_` 開頭之個人存取權杖 |
| `azure_storage_key_generic` | Azure Storage AccountKey | **90** | Critical | 獨立的 Azure 帳戶金鑰特徵 |
| `azure_sas_uri` | Azure SAS URI | **90** | Critical | 包含 SAS 簽章的金鑰網址 |
| `xai_api_key` | xAI API Key | **85** | High | `xai-` 開頭之 API 金鑰 |
| `groq_api_key` | Groq API Key | **85** | High | `gsk_` 開頭之金鑰 |
| `openrouter_api_key` | OpenRouter API Key | **85** | High | `sk-or-v1-` 開頭之金鑰 |
| `replicate_api_token` | Replicate API Token | **85** | High | `r8_` 開頭之 Token |
| `google_api_key` | Google API Key | **85** | High | `AIza` 開頭之 Google API 密鑰 |
| `sentry_auth_token` | Sentry Auth Token | **85** | High | `sntrys_` 開頭之 Sentry 授權權杖 |
| `aws_access_key_id` | AWS Access Key ID | **85** | High | `AKIA` 或 `ASIA` 開頭之 16 碼識別碼 |
| `heroku_api_key_context` | Heroku API Key | **85** | High | 需搭配 `HEROKU_API_KEY` 變數偵測 |
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
| `jwt` | JWT (JSON Web Token) | **75** | High | 以 `eyJ` 開頭的 JWT 連續字串 |
| `twilio_account_sid` | Twilio Account SID | **70** | Medium | `AC` 開頭的 32 碼識別碼 |
| `twilio_api_key_sid` | Twilio API Key SID | **70** | Medium | `SK` 開頭的 32 碼識別碼 |
| `taiwan_citizen_certificate` | 台灣自然人憑證號碼 | **60** | Medium | **台灣個資**：2 碼大寫英文字母 + 14 碼數字 |
| `taiwan_mobile` | 台灣手機號碼 | **50** | Medium | **台灣個資**：`09` 或 `+8869` 開頭共 10 碼（支援 `-` 或空格） |
| `taiwan_einvoice_barcode` | 台灣電子發票手機條碼載具 | **20** | Low | **台灣個資**：`/` 開頭共 8 碼（符合載具字元特徵），本身不具機密性，風險極低 |
| `certificate_pem` | PEM Certificate | **25** | Low | PEM 格式憑證公開部分 |
| `ssh_public_key` | SSH Public Key | **20** | Low | SSH 公開金鑰 |

---

## 3. 風險分數微調規則 (Context Adjustments)

在掃描到潛在密鑰後，系統會結合檔案位置與周圍上下文對基礎分數進行增減：

### A. 檔案路徑與命名加成
*   **環境變數檔案 (Env Files)**：
    *   若檔案路徑後綴為 `.env` 或包含 `.env.`，分數 **`+8`**。
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
*   **Google API Key 於 Firebase 的扣分**：
    *   當規則為 `google_api_key`，且檔案路徑包含 `firebase`、`google-services.json`、`googleservice-info.plist` 或內容含 `firebaseconfig` 時，因通常為公開設定，分數 **`-55`**。
*   **AWS Access Key ID 存在 Secret Key 的加成**：
    *   當規則為 `aws_access_key_id`，且同一檔案中亦偵測到 `secret_access_key` 關鍵字時，分數 **`+10`**。

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
3.  **說明文件範例**：
    *   若檔案路徑中含有 `readme`、`docs/`、`documentation` 或 `guide`。
    *   且檢出的密鑰值中包含 `example`、`sample` 或 `dummy`。
