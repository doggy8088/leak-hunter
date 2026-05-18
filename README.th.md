# leak-hunter

<p align="center">
  <img src="docs/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**ภาษา:** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter` คือ CLI สำหรับสแกนข้อมูลลับใน repository แบบเน้นการป้องกันและทำงานบนเครื่องเป็นหลัก เครื่องมือนี้มี binary ข้ามแพลตฟอร์มตัวเดียวสำหรับสแกน GitHub repository URL, รูปแบบย่อ `owner/repo`, GitHub SSH target หรือโฟลเดอร์ภายในเครื่อง แล้วส่งออกรายงาน Text, JSON หรือ Markdown

Rust crate คือ implementation หลักเพียงส่วนเดียว ส่วน npm package `leak-hunter` เป็นเพียง thin wrapper สำหรับติดตั้งและเรียกใช้ native binary ที่ cargo-dist สร้างไว้ใน GitHub Releases

## การติดตั้ง

```bash
cargo install --path .
```

หรือติดตั้งผ่าน npm package:

```bash
npm install -g leak-hunter
leak-hunter --help
```

## เริ่มต้นอย่างรวดเร็ว

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

GitHub target ที่รองรับ:

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## ตัวเลือก CLI

| ตัวเลือก | คำอธิบาย |
|---|---|
| `--json` | ส่งออก JSON แบบ machine-readable เป็น shortcut สำหรับ JSON report |
| `--format <text\|json\|markdown>` | เลือกรูปแบบรายงาน |
| `--output <path>` | เขียนรายงานลงไฟล์และสร้าง parent directory เมื่อจำเป็น |
| `--min-risk <0-100>` | แสดงเฉพาะ findings ที่ถึงหรือสูงกว่า risk threshold |
| `--include <glob>` / `--exclude <glob>` | จำกัดขอบเขตการสแกน และระบุซ้ำได้ |
| `--no-default-exclude` | ปิดกฎ exclude ที่มีมาให้ |
| `--max-file-size-mb <n>` | ตั้งค่าขนาดสูงสุดต่อไฟล์ที่จะสแกน |
| `--concurrency <n>` | ตั้งค่าจำนวนไฟล์ที่สแกนพร้อมกัน |
| `--no-redact` | แสดงค่า secret ต้นฉบับ ใช้เฉพาะการตรวจสอบด้วยตนเองบนเครื่องเท่านั้น |
| `--keep-temp` | เก็บ temporary clones สำหรับ GitHub targets |
| `--cache-dir <dir>` | ตั้งค่าไดเรกทอรี temporary clone ของ GitHub ค่าเริ่มต้นคือ `.leak-hunter-cache` |
| `--branch <name>` | สแกน branch หรือ tag ที่ระบุ |
| `--debug` | พิมพ์การตัดสินใจสแกน คะแนน candidate finding และเหตุผลการกรอง min-risk ไปยัง stderr |
| `-v, --version` | แสดงข้อมูลเวอร์ชัน |

`--json` และ `--format` ที่ระบุชัดเจนใช้ร่วมกันไม่ได้ เพื่อป้องกัน output ที่กำกวมใน CI scripts

## รายงาน

Text report เหมาะสำหรับอ่านโดยตรงใน terminal:

```bash
leak-hunter . --format text
```

รายงานเริ่มด้วย Leak Hunter ASCII banner และมี target, scan root ที่ resolve แล้ว, เวลา scan, จำนวนไฟล์ที่ scan และ skip, จำนวน finding, risk buckets, สถานะ redaction และตาราง finding

JSON report เหมาะสำหรับเก็บเป็น CI artifacts, ประมวลผลด้วย `jq` หรือส่งเข้า systems อื่น:

```bash
leak-hunter . --json --output leak-hunter-report.json
```

ตัวอย่าง query findings ที่มีความเสี่ยงสูง:

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## กลยุทธ์การสแกน

1. Resolve target ที่เป็น local หรือ GitHub
2. Clone GitHub repository ไปยัง `.leak-hunter-cache` หรือไดเรกทอรีที่กำหนดด้วย `--cache-dir`
3. เดินไฟล์ด้วย gitignore-aware walker และ include / exclude glob
4. ข้าม binary files หรือ files ที่เกินขนาดสูงสุด
5. ใช้ pattern inventory ที่มีมาให้และ context-aware risk model
6. ลด noise ที่พบบ่อยจาก npm integrity hashes ใน package-lock, Firebase public API key context และ paths แบบ docs/example
7. เปิด redaction เป็นค่าเริ่มต้น แล้วเรียง output ตาม risk score, path และ position
8. ลบ temporary GitHub clones เว้นแต่ใช้ `--keep-temp`

## จุดเด่นการตรวจจับ

rules ปัจจุบันครอบคลุม:

- OpenAI, Google API Key, GitHub Token, Stripe, Slack, Sentry และ Docker Hub PAT
- AWS access key / secret key pairing
- Azure Storage connection string / AccountKey / SAS URI
- Popular framework app secrets เช่น Django, Flask, Rails, Laravel, NextAuth, Nuxt, Spring และ ASP.NET
- Database connection strings and URIs เช่น SQL Server-style connection string, PostgreSQL, MongoDB และ Redis
- JWT, PEM private key, GCP service account JSON และ Google OAuth client secret

## npm package และ checksum

`npm/postinstall.cjs` จะแมป platform ปัจจุบันไปยัง cargo-dist target, ดาวน์โหลด release archive และไฟล์ `.sha256` ที่ตรงกัน, ตรวจสอบ SHA-256 checksum แล้วจึงแตกไฟล์และติดตั้ง native binary การ publish ผ่าน npm ใช้ Trusted Publishing / OIDC แทน `NPM_TOKEN` ระยะยาว ก่อน publish คำสั่ง `prepublishOnly` จะรัน npm tests, `npm pack --dry-run` และตรวจสอบว่า release archive กับ checksum ทุกไฟล์มีอยู่ครบ

## การพัฒนา

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

## ความปลอดภัย

Redaction เปิดใช้งานเป็นค่าเริ่มต้น ห้ามเผยแพร่รายงานที่ยังไม่ได้ redact Test fixtures ต้องใช้ synthetic values ที่ประกอบจากชิ้นส่วนของสตริงเพื่อไม่ให้ GitHub push protection ทำงาน
