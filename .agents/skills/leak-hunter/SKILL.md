---
name: leak-hunter
description: Use when agent needs to run or guide leak-hunter, the repository secret scanner, to detect likely leaked secrets in local folders or GitHub repositories; produce JSON reports for AI/tool integrations; inspect findings safely; configure scans with include/exclude, risk thresholds, redaction, GitHub target resolution, or CI/security workflows.
---

# Leak Hunter

Prefer JSON output for agent workflows:

```bash
leak-hunter --json --min-risk 40 .
```

If running inside this source tree:

```bash
cargo run --quiet -- --json --min-risk 40 .
```

Keep redaction enabled unless the user explicitly asks for raw values. Do not publish unredacted reports.
