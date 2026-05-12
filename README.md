# analyze-pcap-dast-action

Uses the output from [capture-pcap-action](https://github.com/caseware/capture-pcap-action) and analyses it with DAST tools. Contains two composite actions:

## Actions

### `create-passive-dast-map`

Downloads PCAP bundles from S3 (last N hours), extracts mitmproxy flow files, and generates site maps in three formats:

| Format | File | Compatible With |
|--------|------|-----------------|
| HAR 1.2 | `sitemap.har` | ZAP, Burp Suite, Rapid7, Chrome DevTools |
| URL list | `urls.txt` | ZAP import, Rapid7 bulk URL add |
| Burp XML | `sitemap-burp.xml` | Burp Suite native import |

```yaml
- uses: caseware/analyze-pcap-dast-action/create-passive-dast-map@v1
  id: sitemap
  with:
    s3-bucket: 'my-pcap-bucket'
    s3-prefix: 'pcap-captures'
    hours: '24'
    filter-domains: '*.myapp.com'
```

#### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `s3-bucket` | Yes | — | S3 bucket containing PCAP bundles |
| `s3-prefix` | No | `pcap-captures` | S3 key prefix to search |
| `s3-endpoint` | No | — | Custom S3 endpoint (MinIO, LocalStack) |
| `hours` | No | `24` | Look-back window in hours |
| `output-dir` | No | `$RUNNER_TEMP/dast-map` | Output directory |
| `filter-domains` | No | — | Domain allowlist (glob patterns) |
| `filter-exclude-domains` | No | — | Domain denylist (glob patterns) |
| `filter-status-codes` | No | — | HTTP status codes to include |
| `filter-methods` | No | — | HTTP methods to include |

#### Outputs

| Output | Description |
|--------|-------------|
| `har-file` | Path to generated HAR file |
| `url-list` | Path to URL list (one per line) |
| `burp-xml` | Path to Burp Suite XML site map |
| `url-count` | Number of unique URLs |
| `domain-count` | Number of unique domains |

### `analyze-pcap-dast`

Runs OWASP ZAP in passive scan mode against a HAR file and produces SARIF output for the GitHub Security tab.

```yaml
- uses: caseware/analyze-pcap-dast-action/analyze-pcap-dast@v1
  with:
    har-file: ${{ steps.sitemap.outputs.har-file }}
    fail-on-risk: 'medium'
    upload-sarif: 'true'
```

#### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `har-file` | Yes | — | Path to HAR file to analyze |
| `sarif-file` | No | `$RUNNER_TEMP/zap-results.sarif` | Output SARIF path |
| `fail-on-risk` | No | `none` | Fail threshold: `none`, `low`, `medium`, `high` |
| `zap-docker-image` | No | `ghcr.io/zaproxy/zaproxy:stable` | ZAP Docker image |
| `upload-sarif` | No | `true` | Upload SARIF to GitHub Security |
| `target-url` | No | — | Target URL for SARIF metadata |

#### Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to SARIF results |
| `alert-count` | Total alerts found |
| `high-count` | High-risk alerts |
| `medium-count` | Medium-risk alerts |
| `low-count` | Low-risk alerts |

## Full Pipeline Example

```yaml
jobs:
  e2e:
    runs-on: ubuntu-24.04-arm
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      # Start capturing traffic
      - uses: caseware/capture-pcap-action/start@v1
        id: pcap
        with:
          filter-domains: '*.myapp.com'

      # Run your e2e tests here
      - run: npm run test:e2e

      # Stop capture and upload to S3
      - uses: caseware/capture-pcap-action/stop@v1
        with:
          s3-bucket: 'pcap-bucket'

  dast:
    needs: e2e
    runs-on: ubuntu-24.04-arm
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      # Generate site map from captured traffic
      - uses: caseware/analyze-pcap-dast-action/create-passive-dast-map@v1
        id: sitemap
        with:
          s3-bucket: 'pcap-bucket'
          hours: '1'

      # Run passive DAST analysis
      - uses: caseware/analyze-pcap-dast-action/analyze-pcap-dast@v1
        with:
          har-file: ${{ steps.sitemap.outputs.har-file }}
          fail-on-risk: 'medium'
```

## CI

All workflows run on `ubuntu-24.04-arm` (ARM64-first). The repo dogfoods both actions by capturing traffic to its own GitHub.com page and analyzing it with ZAP.

- **Integration test** — captures HTTPS traffic via mitmproxy, generates site maps, runs ZAP passive scan, uploads SARIF
- **CodeQL** — scans Python and Actions YAML via `caseware/codeql-arm64-compat`
- **Commitlint** — enforces Conventional Commits

## License

MIT — see [LICENSE](LICENSE).
