# leak-hunter

<p align="center">
  <img src="public/assets/leak-hunter-banner.png" alt="leak-hunter repository secret scanner banner" width="100%">
</p>

**언어:** [English](README.md) | [繁體中文](README.zh-tw.md) | [简体中文](README.zh-cn.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Tiếng Việt](README.vi.md) | [ไทย](README.th.md) | [Français](README.fr.md) | [Deutsch](README.de.md)

`leak-hunter`는 로컬 실행을 우선하는 방어용 저장소 비밀 정보 스캔 CLI입니다. 하나의 크로스 플랫폼 binary로 GitHub repository URL, `owner/repo` 축약 표기, GitHub SSH target, 또는 로컬 폴더를 스캔하고 Text, JSON, Markdown 보고서를 출력합니다.

Rust crate가 유일한 핵심 구현입니다. npm package `leak-hunter`는 GitHub Releases에서 cargo-dist가 만든 native binary를 설치하고 실행하는 thin wrapper입니다.

## 설치

```bash
cargo install --path .
```

또는 npm package를 사용합니다.

```bash
npm install -g leak-hunter
leak-hunter --help
```

## 빠른 시작

```bash
leak-hunter .
leak-hunter --json --min-risk 50 .
leak-hunter --format markdown --output leak-hunter-report.md owner/repo
```

지원되는 GitHub target:

```bash
leak-hunter https://github.com/doggy8088/holidaybook
leak-hunter github.com/doggy8088/holidaybook
leak-hunter doggy8088/holidaybook
leak-hunter git@github.com:doggy8088/holidaybook.git
```

## CLI 옵션

| 옵션 | 설명 |
|---|---|
| `--json` | machine-readable JSON을 출력합니다. JSON report shortcut입니다. |
| `--format <text\|json\|markdown>` | 보고서 형식을 선택합니다. |
| `--output <path>` | 보고서를 파일로 쓰고 필요하면 부모 디렉터리를 만듭니다. |
| `--min-risk <0-100>` | 지정한 위험 임계값 이상의 findings만 표시합니다. |
| `--include <glob>` / `--exclude <glob>` | 스캔 범위를 제한하며 여러 번 지정할 수 있습니다. |
| `--no-default-exclude` | 내장 제외 규칙을 비활성화합니다. |
| `--max-file-size-mb <n>` | 파일별 스캔 크기 제한을 설정합니다. |
| `--concurrency <n>` | 병렬로 스캔할 파일 수를 설정합니다. |
| `--no-redact` | secret 원문 값을 출력합니다. 로컬 수동 검토에만 사용하세요. |
| `--keep-temp` | GitHub target의 임시 clone을 보관합니다. |
| `--cache-dir <dir>` | GitHub 임시 clone 디렉터리를 지정합니다. 기본값은 `.leak-hunter-cache`입니다. |
| `--branch <name>` | 특정 branch 또는 tag를 스캔합니다. |
| `--debug` | 스캔 결정, 후보 finding 점수, min-risk 필터링 이유를 stderr로 출력합니다. |
| `-v, --version` | 버전 정보를 표시합니다. |

`--json`과 명시적인 `--format`은 함께 사용할 수 없습니다. CI 스크립트가 모호한 출력을 만들지 않도록 하기 위한 것입니다.

## 보고서

Text report는 터미널에서 직접 읽기에 적합합니다.

```bash
leak-hunter . --format text
```

보고서는 Leak Hunter ASCII banner로 시작하며 target, 실제 scan root, 스캔 시간, 스캔 및 건너뛴 파일 수, finding 수, risk bucket, redaction 상태, finding table을 포함합니다.

JSON report는 CI 보관, `jq` 처리, 다른 시스템으로 가져오기에 적합합니다.

```bash
leak-hunter . --json --output leak-hunter-report.json
```

고위험 finding 조회 예시:

```bash
leak-hunter . --json \
  | jq '.findings[] | select(.riskScore >= 75) | {type, filePath, lineNumber, riskScore}'
```

## 스캔 전략

1. 로컬 또는 GitHub target을 해석합니다.
2. GitHub repository는 `.leak-hunter-cache` 또는 `--cache-dir`로 지정한 디렉터리에 clone합니다.
3. gitignore-aware walker와 include / exclude glob을 사용합니다.
4. binary 파일이나 크기 제한을 초과한 파일은 건너뜁니다.
5. 내장 pattern inventory와 context-aware risk model을 적용합니다.
6. package-lock npm integrity hashes, Firebase public API key context, docs/example 경로 같은 일반적인 noise를 줄입니다.
7. 기본적으로 redaction을 적용하고 위험 점수, 경로, 위치 순으로 정렬해 출력합니다.
8. `--keep-temp`를 사용하지 않으면 GitHub 임시 clone을 삭제합니다.

## 탐지 하이라이트

현재 재구성된 rules는 다음을 포함합니다.

- OpenAI, Google API Key, GitHub Token, Stripe, Slack, Sentry, Docker Hub PAT
- AWS access key / secret key pairing
- Azure Storage connection string / AccountKey / SAS URI
- Django, Flask, Rails, Laravel, NextAuth, Nuxt, Spring, ASP.NET 등 popular framework app secrets
- SQL Server-style connection string, PostgreSQL, MongoDB, Redis 등 database connection strings and URIs
- JWT, PEM private key, GCP service account JSON, Google OAuth client secret

## npm package와 checksum

`npm/postinstall.cjs`는 현재 플랫폼을 cargo-dist target에 매핑하고 release archive와 해당 `.sha256`을 다운로드한 뒤 SHA-256 checksum을 검증한 후 native binary를 압축 해제해 설치합니다. npm publish는 장기 `NPM_TOKEN` 대신 Trusted Publishing / OIDC를 사용합니다. 게시 전 `prepublishOnly`는 npm tests, `npm pack --dry-run`을 실행하고 모든 release archive와 checksum이 존재하는지 확인합니다.

## 개발

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

## 안전

Redaction은 기본적으로 활성화되어 있습니다. redaction되지 않은 보고서를 게시하지 마세요. 테스트 fixture는 synthetic values를 사용하고 GitHub push protection이 트리거되지 않도록 문자열 조각으로 조립해야 합니다.
