# leak-hunter

<p align="center">
  <img src="docs/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**Ngôn ngữ:** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter` là CLI quét bí mật trong repository theo hướng phòng thủ và ưu tiên chạy cục bộ. Công cụ cung cấp một binary đa nền tảng để quét GitHub repository URL, dạng rút gọn `owner/repo`, GitHub SSH target, hoặc thư mục cục bộ, rồi xuất báo cáo Text, JSON hoặc Markdown.

Rust crate là phần triển khai lõi duy nhất. npm package `leak-hunter` chỉ là thin wrapper để cài đặt và chạy native binary do cargo-dist tạo trong GitHub Releases.

## Cài đặt

```bash
cargo install --path .
```

Hoặc dùng npm package:

```bash
npm install -g leak-hunter
leak-hunter --help
```

## Bắt đầu nhanh

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

Các GitHub target được hỗ trợ:

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## Tùy chọn CLI

| Tùy chọn | Mô tả |
|---|---|
| `--json` | Xuất JSON machine-readable; shortcut cho JSON report. |
| `--format <text\|json\|markdown>` | Chọn định dạng báo cáo. |
| `--output <path>` | Ghi báo cáo ra file và tạo thư mục cha khi cần. |
| `--min-risk <0-100>` | Chỉ hiển thị findings đạt hoặc vượt ngưỡng rủi ro. |
| `--include <glob>` / `--exclude <glob>` | Giới hạn phạm vi quét; có thể lặp lại. |
| `--no-default-exclude` | Tắt các quy tắc loại trừ tích hợp. |
| `--max-file-size-mb <n>` | Đặt giới hạn kích thước quét cho từng file. |
| `--concurrency <n>` | Đặt số file được quét song song. |
| `--no-redact` | Xuất giá trị secret gốc; chỉ dùng để rà soát thủ công cục bộ. |
| `--keep-temp` | Giữ lại temporary clones cho GitHub targets. |
| `--cache-dir <dir>` | Đặt thư mục temporary clone của GitHub; mặc định là `.leak-hunter-cache`. |
| `--branch <name>` | Quét một branch hoặc tag cụ thể. |
| `--debug` | In quyết định quét, điểm candidate finding và lý do lọc min-risk ra stderr. |
| `-v, --version` | In thông tin phiên bản. |

`--json` và `--format` chỉ định rõ là loại trừ lẫn nhau để tránh output mơ hồ trong CI scripts.

## Báo cáo

Text report phù hợp để đọc trực tiếp trong terminal:

```bash
leak-hunter . --format text
```

Báo cáo bắt đầu bằng Leak Hunter ASCII banner và bao gồm target, scan root đã phân giải, thời gian quét, số file đã quét và bỏ qua, số finding, risk buckets, trạng thái redaction và bảng finding.

JSON report phù hợp cho CI artifacts, xử lý bằng `jq` hoặc nhập vào hệ thống khác:

```bash
leak-hunter . --json --output leak-hunter-report.json
```

Ví dụ truy vấn findings rủi ro cao:

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## Chiến lược quét

1. Phân giải target cục bộ hoặc GitHub.
2. Clone GitHub repository vào `.leak-hunter-cache` hoặc thư mục được chỉ định bằng `--cache-dir`.
3. Duyệt file bằng gitignore-aware walker và include / exclude glob.
4. Bỏ qua binary files hoặc files vượt quá giới hạn kích thước.
5. Áp dụng pattern inventory tích hợp và context-aware risk model.
6. Giảm nhiễu phổ biến từ npm integrity hashes trong package-lock, Firebase public API key context và các đường dẫn docs/example.
7. Redaction mặc định, rồi sắp xếp output theo risk score, path và position.
8. Xóa temporary GitHub clones trừ khi dùng `--keep-temp`.

## Điểm nổi bật về phát hiện

Các rules hiện tại bao phủ:

- OpenAI, Google API Key, GitHub Token, Stripe, Slack, Sentry và Docker Hub PAT
- AWS access key / secret key pairing
- Azure Storage connection string / AccountKey / SAS URI
- Popular framework app secrets như Django, Flask, Rails, Laravel, NextAuth, Nuxt, Spring và ASP.NET
- Database connection strings and URIs như SQL Server-style connection string, PostgreSQL, MongoDB và Redis
- JWT, PEM private key, GCP service account JSON và Google OAuth client secret

## npm package và checksum

`npm/postinstall.cjs` ánh xạ nền tảng hiện tại sang cargo-dist target, tải release archive và file `.sha256` tương ứng, xác minh SHA-256 checksum, rồi giải nén và cài đặt native binary. npm publishing dùng Trusted Publishing / OIDC thay vì `NPM_TOKEN` dài hạn. Trước khi publish, `prepublishOnly` chạy npm tests, `npm pack --dry-run` và xác nhận mọi release archive cùng checksum đều tồn tại.

## Phát triển

```bash
cargo fmt --all -- --check
cargo test
cargo build --release
npm test
npm pack --dry-run
```

Self-scan:

```bash
cargo run --quiet -- --json --min-risk 40 . \
  | jq '{findings: .summary.findings, filesEnumerated: .summary.filesEnumerated}'
```

## An toàn

Redaction được bật mặc định. Không công bố báo cáo chưa được redact. Test fixtures phải dùng synthetic values được ghép từ các mảnh chuỗi để không kích hoạt GitHub push protection.
