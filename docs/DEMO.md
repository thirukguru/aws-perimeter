# AWS Perimeter Demo Playbook

This document gives you a complete demo flow with commands and flags to showcase `aws-perimeter` capabilities.

## 1. Setup

```bash
# from repo root
go fmt ./...
go test ./...
go build -o bin/aws-perimeter .
```

## 2. Quick Sanity Commands

```bash
./bin/aws-perimeter --version
./bin/aws-perimeter --profile default --region us-east-1
./bin/aws-perimeter --rules > rules.md
./bin/aws-perimeter --capabilities > capabilities.md
```

## 3. Core Scan Showcase

```bash
# table output (default)
./bin/aws-perimeter --profile default --region us-east-1

# json output
./bin/aws-perimeter --profile default --region us-east-1 --output json

# json output + jq (clean machine-readable output)
./bin/aws-perimeter --profile default --region us-east-1 --output json | jq .

# multi-region json (single aggregated top-level JSON document)
./bin/aws-perimeter --profile default --regions us-east-1,us-west-2 --output json | jq .

# inspect aggregate counters
./bin/aws-perimeter --profile default --regions us-east-1,us-west-2 --output json | jq '.summary'

# html report
./bin/aws-perimeter --profile default --region us-east-1 --output html --output-file reports/security-report.html
```

## 4. Multi-Region Showcase

```bash
# explicit region list
./bin/aws-perimeter --profile default --regions us-east-1,us-west-2,eu-west-1 --max-parallel 4

# all enabled regions
./bin/aws-perimeter --profile default --all-regions --max-parallel 5

# best effort mode (non-zero exit only if all regions fail)
./bin/aws-perimeter --profile default --regions us-east-1,us-west-2,eu-west-1 --max-parallel 4 --best-effort

# multi-region html writes one file per region (region + datetime suffix added automatically)
./bin/aws-perimeter --profile default --regions us-east-1,us-west-2 --output html --output-file reports/security-report.html
```

## 5. Multi-Account (Organizations) Showcase

```bash
# default member role name
./bin/aws-perimeter --profile default --org-scan --max-parallel 3

# custom role name + external ID
./bin/aws-perimeter --profile default --org-scan \
  --org-role-name SecurityAuditRole \
  --external-id perimeter-demo-2026 \
  --max-parallel 4
```

## 6. Historical Storage + Trends Showcase

```bash
# run scan and persist to sqlite
./bin/aws-perimeter --profile default --region us-east-1 --store

# run multi-region and persist
./bin/aws-perimeter --profile default --regions us-east-1,us-west-2 --store --max-parallel 4

# trend table (30 days)
./bin/aws-perimeter --trends --trend-days 30

# trend + scan comparison
./bin/aws-perimeter --trends --trend-days 60 --compare

# filter trends by account
./bin/aws-perimeter --trends --trend-days 30 --account-id 123456789012

# export trends
./bin/aws-perimeter --trends --trend-days 30 --export-json reports/trends.json --export-csv reports/trends.csv

# custom db path
./bin/aws-perimeter --store --db-path ~/.aws-perimeter/history-demo.db
./bin/aws-perimeter --trends --db-path ~/.aws-perimeter/history-demo.db --trend-days 30
```

## 7. History Commands Showcase

```bash
# list recent scans
./bin/aws-perimeter history list

# list with filters/options
./bin/aws-perimeter history list --db-path ~/.aws-perimeter/history.db --account-id 123456789012 --limit 50

# show findings for one scan
./bin/aws-perimeter history show 42

# finding lifecycle by hash
./bin/aws-perimeter history finding d3c1ff...hash
```

## 8. DB Maintenance Showcase

```bash
# vacuum
./bin/aws-perimeter db vacuum

# reindex
./bin/aws-perimeter db reindex

# purge scans older than N days
./bin/aws-perimeter db purge --older-than 90

# custom DB path
./bin/aws-perimeter db vacuum --db-path ~/.aws-perimeter/history-demo.db
```

## 9. Dashboard + API Showcase

```bash
# start dashboard server
./bin/aws-perimeter dashboard --port 8080

# with account and DB filter
./bin/aws-perimeter dashboard --db-path ~/.aws-perimeter/history.db --account-id 123456789012 --port 8090
```

```bash
# API smoke checks (run in another terminal)
curl http://localhost:8080/api/trends
curl http://localhost:8080/api/scans
curl "http://localhost:8080/api/findings?scan_id=42"
```

## 10. Remediation Flags Showcase

```bash
# preview mode
./bin/aws-perimeter --profile default --region us-east-1 --dry-run

# apply supported remediations
./bin/aws-perimeter --profile default --region us-east-1 --remediate
```

## 11. Full Capability Demo (End-to-End)

```bash
# 1) org-wide persisted scan
./bin/aws-perimeter --profile default --org-scan --store --max-parallel 4

# 2) historical trend + comparison + exports
./bin/aws-perimeter --trends --trend-days 30 --compare \
  --export-json reports/org-trends.json \
  --export-csv reports/org-trends.csv

# 3) dashboard for leadership walkthrough
./bin/aws-perimeter dashboard --port 8080
```

---

## 12. Fanout Control Flags

- `--max-parallel`: controls concurrent region/account scan units in fanout modes (`--regions`, `--all-regions`, `--org-scan`).
- `--best-effort`: for multi-region scans, exits with success if at least one region succeeds (failures still captured in output).

```bash
# balanced concurrency
./bin/aws-perimeter --profile default --regions us-east-1,us-west-2,eu-west-1 --max-parallel 4

# tolerate partial regional failures
./bin/aws-perimeter --profile default --regions us-east-1,us-west-2,eu-west-1 --max-parallel 4 --best-effort
```

---

## Root Flags (Complete)

| Flag | Short | Type | Example |
|---|---|---|---|
| `--profile` | `-p` | string | `--profile default` |
| `--region` | `-r` | string | `--region us-east-1` |
| `--regions` | | csv string | `--regions us-east-1,us-west-2` |
| `--all-regions` | | bool | `--all-regions` |
| `--org-scan` | | bool | `--org-scan` |
| `--org-role-name` | | string | `--org-role-name OrganizationAccountAccessRole` |
| `--external-id` | | string | `--external-id perimeter-demo-2026` |
| `--version` | `-v` | bool | `--version` |
| `--output` | `-o` | string | `--output json` |
| `--rules` | | bool | `--rules` |
| `--capabilities` | | bool | `--capabilities` |
| `--output-file` | `-f` | string | `--output-file report.html` |
| `--store` | | bool | `--store` |
| `--db-path` | | string | `--db-path ~/.aws-perimeter/history.db` |
| `--trends` | | bool | `--trends` |
| `--trend-days` | | int | `--trend-days 30` |
| `--compare` | | bool | `--compare` |
| `--export-json` | | string | `--export-json reports/trends.json` |
| `--export-csv` | | string | `--export-csv reports/trends.csv` |
| `--account-id` | | string | `--account-id 123456789012` |
| `--max-parallel` | | int | `--max-parallel 4` |
| `--best-effort` | | bool | `--best-effort` |
| `--dry-run` | | bool | `--dry-run` |
| `--remediate` | | bool | `--remediate` |
| `--dashboard-port` | | int | `--dashboard-port 8080` |
| `--config-path` | | string | `--config-path ./aws-perimeter.yaml` |

Note: for the dashboard subcommand, use `dashboard --port` (subcommand flag).

## Subcommand Flags (Complete)

### `db`

| Flag | Type | Example |
|---|---|---|
| `--db-path` | string | `aws-perimeter db vacuum --db-path ~/.aws-perimeter/history.db` |
| `--older-than` | int | `aws-perimeter db purge --older-than 60` |

Subcommands: `vacuum`, `reindex`, `purge`

### `history`

| Flag | Type | Example |
|---|---|---|
| `--db-path` | string | `aws-perimeter history list --db-path ~/.aws-perimeter/history.db` |
| `--account-id` | string | `aws-perimeter history list --account-id 123456789012` |
| `--limit` | int | `aws-perimeter history list --limit 100` |

Subcommands: `list`, `show <scan-id>`, `finding <hash>`

### `dashboard`

| Flag | Type | Example |
|---|---|---|
| `--db-path` | string | `aws-perimeter dashboard --db-path ~/.aws-perimeter/history.db` |
| `--account-id` | string | `aws-perimeter dashboard --account-id 123456789012` |
| `--port` | int | `aws-perimeter dashboard --port 8080` |

## Demo Tips

- Use `--store` in all demo scans so trend/dashboard pages always have data.
- Run at least two scans (different times) before showing `--compare`.
- For org demo, ensure `organizations:ListAccounts` and `sts:AssumeRole` are allowed.
- If `history list` is empty, verify the same `--db-path` is used for scan and query.
- In JSON mode (`--output json`), banner/spinner are disabled and output is one valid JSON object.
- In multi-region mode, JSON emits one aggregated top-level document (no scan/progress/summary noise in stdout).
  Aggregate JSON includes `summary`, `results`, and `failures`.
- In fanout modes with HTML output, `--output-file` is used as a base name and region/account + datetime suffixes are appended.
- In HTML mode, terminal table output is suppressed; only concise summary lines are printed.
- `--rules` and `--capabilities` are no-scan modes that print Markdown to stdout (safe to redirect to files).
