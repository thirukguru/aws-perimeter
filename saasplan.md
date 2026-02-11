# AWS Doctor SaaS Plan

## 1. Product Goal
Build AWS Doctor into a multi-tenant SaaS platform that provides:
- Continuous cloud security posture management
- Cost optimization with security-aware guardrails
- AI-assisted risk prioritization and remediation guidance
- Multi-account and multi-region visibility for AWS Organizations

## 2. SaaS Scope After Roadmap Completion
- Expose all scan capabilities through versioned APIs (`/v1/...`)
- Support org-wide onboarding for many AWS accounts per tenant
- Deliver production-grade UI based on `mock/ui.html`
- Add usage-based billing, role-based access, and audit logs

## 3. Target Architecture
- Frontend: SPA (React/Next.js) based on current mock information architecture
- API: Go service layer with REST endpoints and async jobs
- Workers: scan runners executing per account/region/service domain
- Data:
  - Postgres for tenants, accounts, scans, findings, users, billing metadata
  - Object storage for raw scan artifacts and exports
  - Redis/SQS for queueing scan jobs
- Identity:
  - SaaS user auth (OIDC/SAML + email/password)
  - AWS access via cross-account IAM role assumption

## 4. Multi-Tenant Model
- Tenant
  - Multiple users
  - Multiple AWS accounts
  - Multiple scan policies
- RBAC roles
  - `owner`, `admin`, `analyst`, `viewer`, `billing_admin`
- Strict tenant isolation
  - Every query filtered by `tenant_id`
  - Signed role sessions per linked AWS account

## 5. API Plan (Core Platform)
All endpoints under `/v1`.

### Auth and Tenant APIs
- `POST /auth/login`
- `POST /auth/logout`
- `POST /auth/refresh`
- `GET /me`
- `GET /tenants/{tenantId}`
- `PATCH /tenants/{tenantId}`
- `GET /tenants/{tenantId}/members`
- `POST /tenants/{tenantId}/members`
- `PATCH /tenants/{tenantId}/members/{memberId}`

### AWS Account APIs
- `GET /accounts`
- `POST /accounts` (register account + external ID + role ARN)
- `POST /accounts/{accountId}/verify`
- `PATCH /accounts/{accountId}`
- `DELETE /accounts/{accountId}`
- `GET /accounts/{accountId}/regions`

### Scan APIs
- `POST /scans` (on-demand scan)
- `GET /scans`
- `GET /scans/{scanId}`
- `POST /scans/{scanId}/cancel`
- `GET /scans/{scanId}/findings`
- `GET /scans/{scanId}/artifacts`
- `POST /scan-policies`
- `GET /scan-policies`
- `PATCH /scan-policies/{policyId}`

### Findings and Workflow APIs
- `GET /findings`
- `GET /findings/{findingId}`
- `PATCH /findings/{findingId}` (status, assignee, note)
- `POST /findings/{findingId}/snooze`
- `POST /findings/{findingId}/unsnooze`
- `GET /remediations/{findingId}`
- `POST /exports` (json/html/pdf/csv)

### Intelligence and Reporting APIs
- `GET /dashboard/summary`
- `GET /dashboard/trends`
- `GET /intelligence/recommendations`
- `GET /compliance/cis`
- `GET /compliance/fsbp`
- `GET /cost/summary`
- `GET /cost/recommendations`

### Integrations APIs
- `POST /integrations/slack`
- `POST /integrations/pagerduty`
- `POST /integrations/webhooks`
- `POST /integrations/siem/splunk`
- `POST /integrations/siem/elk`

### Billing APIs
- `GET /billing/plans`
- `POST /billing/subscribe`
- `GET /billing/usage`
- `GET /billing/invoices`

## 6. Service Coverage API Matrix
Use domain endpoints to expose all current service modules.

### Security Domain Endpoints
- `GET /security/ec2` -> `service/ec2security`
- `GET /security/s3` -> `service/s3security`
- `GET /security/iam` -> `service/iam`
- `GET /security/iam-advanced` -> `service/iamadvanced`
- `GET /security/lambda` -> `service/lambdasecurity`
- `GET /security/ecs` -> `service/ecssecurity`
- `GET /security/eks` -> `service/ekssecurity`
- `GET /security/ecr` -> `service/ecrsecurity`
- `GET /security/apigateway` -> `service/apigatewaysecurity`
- `GET /security/cloudfront` -> `service/cloudfrontsecurity`
- `GET /security/cloudtrail` -> `service/cloudtrailsecurity`
- `GET /security/event` -> `service/eventsecurity`
- `GET /security/cache` -> `service/cachesecurity`
- `GET /security/aurora` -> `service/aurorasecurity`
- `GET /security/redshift` -> `service/redshiftsecurity`
- `GET /security/resource-policy` -> `service/resourcepolicy`
- `GET /security/route53` -> `service/route53`
- `GET /security/elb` -> `service/elb`
- `GET /security/vpc` -> `service/vpc`
- `GET /security/vpc-advanced` -> `service/vpcadvanced`
- `GET /security/vpc-endpoints` -> `service/vpcendpoints`
- `GET /security/secrets` -> `service/secrets`
- `GET /security/data-protection` -> `service/dataprotection`
- `GET /security/governance` -> `service/governance`
- `GET /security/shield` -> `service/shield`

### Native AWS Security Tool Endpoints
- `GET /security/guardduty` -> `service/guardduty`
- `GET /security/securityhub` -> `service/securityhub`
- `GET /security/inspector` -> `service/inspector`
- `GET /security/aws-config` -> `service/aws_config`
- `GET /security/config` -> `service/config`

### Threat and Intelligence Endpoints
- `GET /security/ai-detection` -> `service/aidetection`
- `GET /security/messaging` -> `service/messaging`

### Platform/Internal Service Endpoints
- `GET /platform/orchestrator` -> `service/orchestrator`
- `GET /platform/output` -> `service/output`
- `GET /platform/logging` -> `service/logging`
- `GET /platform/sts` -> `service/sts`
- `GET /platform/flags` -> `service/flag`
- `GET /platform/storage` -> `service/storage`
- `GET /platform/apigateway` -> `service/apigateway` (platform wiring module)
- `GET /platform/cloudtrail` -> `service/cloudtrail` (platform wiring module)

## 7. UI Plan (Based on `mock/ui.html`)
Keep current page structure and productionize it.

### Information Architecture
- Dashboard
- Security Findings
- Cost Optimization
- Smart Insights
- AWS Accounts

### UI Build Plan
- Build reusable design system tokens (spacing, color, typography, status)
- Replace mock static cards/tables/charts with API-backed components
- Add global filters: account, region, severity, service, date range
- Add finding drill-down drawer with evidence + remediation steps
- Add account onboarding wizard from `+ Connect AWS Account`
- Add background scan status and notifications

### API Mapping to UI Pages
- Dashboard page -> `/dashboard/summary`, `/dashboard/trends`
- Security page -> `/findings`, `/security/*`
- Cost page -> `/cost/summary`, `/cost/recommendations`
- Smart Insights page -> `/intelligence/recommendations`
- AWS Accounts page -> `/accounts`, `/accounts/{id}/verify`

## 8. Delivery Phases

### Phase A: SaaS Foundation
- Tenant model, auth, RBAC, account onboarding
- Scan job queue and scheduler
- Core scan and findings APIs

### Phase B: UI Productionization
- Implement all five pages from mock with live APIs
- Add finding workflow (assign, suppress, resolve)
- Add exports and reports

### Phase C: Enterprise Readiness
- SSO (SAML/OIDC), audit logs, rate limits
- Billing and subscription controls
- Integrations (Slack, PagerDuty, SIEM)

### Phase D: Scale and Intelligence
- Drift detection and trend analytics
- ML-assisted risk prioritization
- Auto-remediation templates and approval workflow

## 9. Non-Functional Requirements
- Security: encryption at rest/in transit, least privilege IAM, signed audit events
- Reliability: retries, idempotency keys, backpressure for scan jobs
- Performance: pagination everywhere, async exports, cache hot dashboard aggregates
- Compliance: SOC 2 controls, CIS/FSBP mapping retention, immutable audit trails

## 10. Pricing and Packaging (Initial)
- Free: 1 account, limited scans, basic dashboard
- Growth: up to N accounts, scheduled scans, exports, Slack alerts
- Enterprise: unlimited accounts, SSO, SIEM, custom retention, priority support

