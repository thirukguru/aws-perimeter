# AWS Perimeter STRIDE Threat Model

**Version:** 1.0.0  
**Last Updated:** 2026-02-11  
**Scope:** AWS Perimeter CLI scanner, report generation, AWS API integrations, local artifact storage

---

## 1. System Scope

AWS Perimeter is a local CLI scanner that:
- Accepts operator input (flags/config)
- Authenticates to AWS using local credentials/assumed roles
- Enumerates cloud resources and security posture signals
- Produces findings and exports (table/json/html)
- Optionally stores history locally (planned SQLite path)

### Trust Boundaries
1. **Operator workstation boundary** (local process, filesystem, terminal)
2. **AWS identity boundary** (IAM principal, STS session, org-account assumptions)
3. **AWS service data boundary** (read APIs from many AWS services)
4. **Output boundary** (stdout, JSON/HTML/PDF artifacts, CI logs)

---

## 2. Assets to Protect

- AWS credentials and temporary STS tokens
- Findings data (can include sensitive architecture details)
- Generated reports and historical scan records
- Rule definitions and severity logic
- Execution integrity of scanner binary and update/install paths

---

## 3. STRIDE Analysis

## S — Spoofing Identity

### Threats
- Use of compromised local AWS credentials or stolen session tokens
- Role-assumption spoofing in cross-account/org scans
- Malicious principal pretending to be approved CI runner/operator

### Existing/Planned Mitigations
- Prefer STS caller identity checks at runtime and include account/arn in report metadata
- Require explicit role allowlists for org scan targets (planned hardening)
- Support MFA-backed role assumption where possible
- Log operator identity, account, and region set for every scan execution

### Residual Risk
- If host is compromised, credentials can still be abused before scan begins

---

## T — Tampering

### Threats
- Local modification of findings/report files before sharing
- Tampered rule pack causing false negatives
- SQLite history tampering to hide/remap risk trends
- Supply-chain tampering in install/update flow

### Existing/Planned Mitigations
- Add optional report signing/checksum output (planned)
- Pin release artifacts/checksums and verify on update path (planned)
- Maintain immutable scan metadata (scan id, timestamp, account) in persisted history
- Restrict write paths and file permissions for local artifacts

### Residual Risk
- Local user with write access can still alter plaintext artifacts without integrity controls

---

## R — Repudiation

### Threats
- Operator denies running a scan or using specific flags
- Unclear provenance of report artifacts in CI/CD pipelines
- Lack of accountability for remediation-triggering decisions

### Existing/Planned Mitigations
- Add execution manifest in outputs: actor arn, account id, regions, commit/version, timestamp
- Persist scan run history (planned trending storage)
- Add deterministic scan IDs and optional audit log mode

### Residual Risk
- Repudiation remains possible if audit artifacts are not centrally retained

---

## I — Information Disclosure

### Threats
- Findings leaking sensitive topology (public endpoints, trust relationships)
- Secrets accidentally included in findings or logs
- Overly verbose errors leaking account internals in CI logs

### Existing/Planned Mitigations
- Redact token/secret-like values in logs and exports
- Add output sanitization modes (`--safe-output`) for CI publishing (planned)
- Classify finding fields as sensitive/non-sensitive before export
- Minimize PII/security-sensitive fields in default console output

### Residual Risk
- JSON/HTML exports may still expose sensitive architecture if shared broadly

---

## D — Denial of Service

### Threats
- API throttling due to high concurrency, especially org+multi-region scans
- Very large estates causing memory/CPU pressure on scanner host
- Repeated expensive queries causing long runtime and failed scans

### Existing/Planned Mitigations
- Bounded concurrency with backoff/retry for AWS API calls
- Service-specific timeouts and cancellation propagation
- Progressive output/progress tracking for long scans
- Caching for repeated expensive checks (where correctness is preserved)

### Residual Risk
- Extreme-scale org scans can still exceed practical runtime without selective scanning

---

## E — Elevation of Privilege

### Threats
- Scanner execution using overly broad IAM permissions
- Risky remediation mode (future) could execute high-impact changes
- Compromised plugin/rule source escalating scanner behavior

### Existing/Planned Mitigations
- Enforce least-privilege read-only baseline for scan mode
- Separate scan vs remediation roles and require explicit confirmation gates
- Introduce policy validation preflight (fail if permissions exceed recommended baseline)
- Treat rule packs as trusted artifacts with version control + review

### Residual Risk
- Misconfigured IAM in customer account can still grant more permissions than intended

---

## 4. Threat Prioritization (Initial)

### High Priority
- Information disclosure via report artifacts
- Tampering of outputs/rule packs without integrity proof
- DoS/throttling in large org scans
- Privilege misuse from over-broad IAM policies

### Medium Priority
- Repudiation gaps (insufficient scan provenance)
- Spoofing in CI contexts lacking identity assertions

### Lower Priority
- Local-only tampering where host trust is already assumed

---

## 5. Security Backlog Derived from STRIDE

1. Add report manifest fields (`actor_arn`, `account_id`, `scan_id`, `version`, `regions`)
2. Add optional report checksum/signature output
3. Add least-privilege IAM policy validator command (`aws-perimeter --validate-iam`)
4. Add sensitive field redaction strategy for JSON/HTML exports
5. Add bounded concurrency + retry/backoff guardrails across services
6. Add immutable scan history records when trending storage is enabled

---

## 6. Verification Plan

- Unit tests for redaction/integrity metadata generation
- Integration tests for throttling/backoff behavior under mocked rate limits
- Contract tests for account/identity provenance fields in all output formats
- Security review checkpoint before enabling remediation capabilities

---

## 7. Out of Scope (This Iteration)

- Full attack graph engine (covered by separate roadmap item: attack path analysis)
- Behavioral anomaly detection pipelines (covered by exfiltration and crypto-mining roadmap items)
- Managed SIEM connector hardening (covered by enterprise integrations roadmap)
