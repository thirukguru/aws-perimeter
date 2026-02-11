# AWS Perimeter Capabilities Overview

AWS Perimeter is a security posture scanner for AWS environments, built for fast visibility across accounts, regions, services, and time. It helps teams detect high-impact exposure, prioritize remediation, and track security drift with clear, actionable output.

## Why Teams Use AWS Perimeter

- Broad AWS coverage across identity, network, storage, logging, containers, and AI/ML surfaces.
- Practical, high-signal findings focused on real attack paths and misconfiguration risks.
- Multi-region and multi-account scanning with consolidated summaries for operational scale.
- Historical storage and trend analysis to measure risk reduction over time.
- CLI-first workflow with JSON/HTML exports and dashboard/API support.

## Core Platform Capabilities

### 1) Security Detection Across AWS Domains

- VPC security: security groups, NACLs, flow logs, public exposure, IMDSv1, management-plane exposure, plaintext protocol risks.
- IAM security: privilege escalation paths, stale credentials, MFA gaps, cross-account trusts, overly permissive policies, missing boundaries.
- S3 security: public access exposure, encryption gaps, risky policies, sensitive file/object discovery.
- CloudTrail security: logging coverage and auditability gaps.
- Native security services: GuardDuty and Security Hub status and finding ingestion.
- Extended checks: ELB, Route53, Config, KMS, backup posture, VPC endpoints, NAT HA, peering, bastion detection, role-chain risks.
- Container security: ECS/EKS workload and control-plane hardening checks.
- AI attack detection: indicators aligned with modern cloud abuse and LLMjacking-style patterns.

### 2) Deep Secrets Detection

- Lambda environment variable scanning.
- Lambda deployment package (ZIP) content scanning.
- EC2 user data scanning.
- Public S3 object content scanning.
- ECR image layer scanning (tar/gzip layer analysis).

### 3) Multi-Region and Multi-Account Operations

- Single-region, selected-region, and all-region scanning modes.
- AWS Organizations account fanout with role assumption and external ID support.
- Bounded parallelism with retry/backoff behavior for rate-limit resilience.
- Best-effort multi-region mode for resilient automation when some regions are temporarily unavailable.
- Consolidated fanout summaries with success/failed/skipped status and account-level rollups.

### 4) Historical Risk Intelligence

- SQLite-backed scan history and lifecycle tracking.
- Trend queries by account/region/time window.
- Scan comparison for new/resolved/persistent findings.
- CLI history commands for scan and finding investigations.
- Export support for trend/report data (JSON/CSV).

### 5) Reporting and Consumption

- Rich terminal tables for analyst workflows.
- JSON output for pipelines and automation.
  Single-region emits one consolidated JSON document.
  Multi-region emits one aggregated top-level JSON document with `summary`, `results`, and `failures`.
  JSON mode suppresses banner/spinner/progress noise for machine parsing.
- HTML report generation for stakeholder sharing.
  Fanout HTML writes one report per scan unit with account/region + timestamp suffixes.
- Local dashboard and API endpoints for trend and finding views.

## Output Designed for Action

- Severity-oriented prioritization (Critical/High/Medium/Low).
- Account and region attribution in findings.
- Clear remediation guidance embedded in findings.
- Consolidated and rollup summaries for leadership/operations visibility.

## Common Use Cases

- Daily/weekly security posture checks across production AWS accounts.
- Pre-deployment and post-change validation in CI/CD pipelines.
- Incident-response enrichment for suspicious IAM/network activity.
- Compliance evidence generation with exported reports and historical trends.
- Security engineering backlogs prioritized by exploitable exposure.

## Operating Modes

- Single account, single region baseline scans.
- Multi-region posture sweeps for global environments.
- Organization-wide scans from management/delegated scanning account.
- Historical mode for trend analysis and lifecycle tracking.
- Dashboard/API mode for local observability workflows.

## Who It Helps

- Cloud security engineers needing deep, service-level visibility.
- Platform/SRE teams enforcing secure defaults at scale.
- DevSecOps teams embedding checks into delivery workflows.
- Security leadership tracking posture improvements over time.

## Security and Safety Model

- Read-focused scanning behavior across AWS services.
- No automatic remediation unless explicitly enabled by future remediation modes.
- IAM least-privilege compatible with scoped permission policies.

## Business Value Summary

AWS Perimeter reduces time-to-detection for cloud misconfiguration and exposure risk, improves security signal quality, and gives teams a scalable workflow for multi-account cloud defense. It combines breadth, depth, and operational usability in a single toolchain.
