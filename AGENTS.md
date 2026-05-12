# AGENTS.md

Guidelines for AI agents (GitHub Copilot, Devin, etc.) contributing to this repo.

## Repository purpose

This is a pair of GitHub Actions that analyze captured PCAP traffic from
`caseware/capture-pcap-action` using DAST (Dynamic Application Security Testing) tools.

The repo contains two composite actions:
- `create-passive-dast-map/` — generates site maps (HAR, URL list, Burp XML) from S3 PCAP bundles
- `analyze-pcap-dast/` — runs ZAP passive scan on HAR files, produces SARIF for GitHub Security

## ARM64-first rule

**All CI jobs that can run on ARM64 must do so.**
Use `ubuntu-24.04-arm` for every job unless the task is architecturally
impossible on ARM64. Do not default to `ubuntu-latest` (x86_64).

## Commit messages — Conventional Commits

All commits **must** follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <subject>

<optional body — lines <= 100 chars>
```

**Allowed types:** `build` `chore` `ci` `docs` `feat` `fix` `perf`
`refactor` `revert` `style` `test`

**Rules enforced by commitlint (CI) and the local pre-commit hook:**
- `subject-empty` — subject must not be empty
- `type-empty` — type must be present
- `body-max-line-length` — body lines must not exceed 100 characters
- Trailers like `Co-authored-by:` are exempt from the line-length rule

**Local hook setup** (one-time, per clone):
```bash
git config core.hooksPath .githooks
```

Do **not** include `Agent-Logs-Url:` or other long auto-generated trailers
in commit bodies; they will exceed the 100-char body line limit.

## Release workflow

A release is triggered by bumping `VERSION` (strict semver `X.Y.Z`) on `main`.
Every PR must include a `VERSION` bump — the `version-bump` CI job enforces this.

## File layout

| Path | Purpose |
|------|---------|
| `create-passive-dast-map/action.yml` | Composite: S3 download → flow extraction → site maps |
| `analyze-pcap-dast/action.yml` | Composite: ZAP passive scan → SARIF output |
| `scripts/flows-to-sitemap.py` | Converts mitmproxy flows to HAR/URL/Burp XML |
| `VERSION` | Strict semver version string |
| `.github/workflows/test.yml` | Integration test (dogfood against GitHub.com) |
| `.github/workflows/codeql.yml` | CodeQL scan (Python + Actions) on ARM64 |
| `.github/workflows/commitlint.yml` | Commit message validation |
| `.githooks/commit-msg` | Local commitlint hook |

## What agents should not do

- Do not use `ubuntu-latest`; use `ubuntu-24.04-arm` for all jobs
- Do not add `Agent-Logs-Url:` lines to commit bodies
- Do not bypass `git config core.hooksPath .githooks`
- Do not hardcode AWS credentials; rely on environment / OIDC
- Do not remove the integration test; it validates the full pipeline
