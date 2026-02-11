# AWS Perimeter - Task Tracker

## Phase 1: Compliance & Core Gaps ✅ COMPLETE
- [x] CIS Benchmark Mapping (47 rules mapped)
- [x] EC2 Security (EBS snapshots, public AMIs)
- [x] CloudFront Security (6 checks)
- [x] API Gateway Security (10 checks)
- [x] Aurora/RDS Security (10 checks)
- [x] PDF Export

**Total: 73 security rules**

---

## Phase 2: Container & Serverless Security 🔄 IN PROGRESS

### ECS Security (10 checks) ✅ SERVICE CREATED
- [x] Task definition privileged containers
- [x] Secrets in environment variables  
- [x] Public task exposure (AssignPublicIp)
- [x] Container runs as root
- [x] Host network mode
- [x] Public container images (non-ECR)
- [x] Writable root filesystem
- [x] Dangerous Linux capabilities
- [x] ECS Exec enabled
- [x] Container Insights disabled

### EKS Security (12 checks) ✅ SERVICE CREATED
- [x] Public endpoint access (0.0.0.0/0)
- [x] No private endpoint
- [x] Control plane logging disabled
- [x] Incomplete logging (api/audit/auth)
- [x] Secrets not encrypted with KMS
- [x] Outdated Kubernetes version
- [x] No OIDC provider for IRSA
- [x] Legacy auth mode (aws-auth ConfigMap)
- [x] Public subnet node groups
- [x] Unrestricted SSH to nodes
- [x] Admin-level node IAM role
- [x] Standard AMI (not Bottlerocket)

### Lambda Enhancements (existing)
- [x] Overly permissive roles detection
- [x] Cross-region execution detection

✅ **ECS/EKS WIRED INTO ORCHESTRATOR** - Build passes, findings in HTML report

---

## Phase 2.5: AI Attack Detection ✅ COMPLETE
*Based on Feb 2025 threat intelligence: 8-minute AWS breach using AI*

### Validation Status (Feb 11, 2026)
- [x] AI findings visible in table, HTML, and JSON outputs
- [x] CloudTrail `UpdateTrail` detection narrowed to risky changes
- [x] Partial detector/API failures surfaced as explicit `AIDetectionError` findings
- [x] Unit tests added for lateral movement, rapid admin access, and CloudTrail gap logic

### GPU Instance Monitoring
- [x] GPU instance detection (p2/p3/p4/p5, g3/g4/g5)
- [x] GPU public IP exposure
- [x] GPU IMDSv1 vulnerability

### Bedrock Abuse Detection
- [x] High capacity provisioned throughput
- [x] Custom Bedrock models
- [x] Bedrock logging disabled

### Rapid Provisioning Detection
- [x] EC2 API throttle detection

### Attack Pattern Detection
- [x] Cross-service lateral movement (role assumption velocity)
- [x] Rapid admin access (privilege escalation in 15 min)
- [x] CloudTrail gaps (StopLogging, DeleteTrail, UpdateTrail)

---

## Phase 3: Security Coverage Expansion 🔲 PLANNED

### Phase 3 - Wave 1 Priority Order
1. SNS/SQS Security (5 checks)
2. ECR Security (5 checks)
3. Backup & Disaster Recovery (5 checks)
4. Organizations & SCP Expansion (4 checks)
5. Lambda Security Expansion (5 checks)

### Lambda Security Expansion (5 checks)
- [x] VPC Lambda without NAT or VPC endpoints
- [x] Lambda layer risks (public/untrusted layers)
- [x] Reserved concurrency set to 0
- [x] Lambda SnapStart with secrets exposure risk
- [x] Function URL without auth

### SNS/SQS Security (5 checks)
- [x] Public SNS topics (`Principal: "*"`)
- [x] Unencrypted SNS topics
- [x] Public SQS queues
- [x] Unencrypted SQS queues
- [x] Missing dead-letter queue

### EventBridge/Step Functions Security (3 checks)
- [x] Open EventBridge bus policy
- [x] Step Functions logging disabled
- [x] State machine public exposure risk

### ECR Security (5 checks)
- [x] Mutable image tags enabled
- [x] No image vulnerability scanning
- [x] Public ECR repository
- [x] ECR encryption with KMS not configured
- [x] No image lifecycle policy

### ElastiCache/MemoryDB Security (5 checks)
- [x] No encryption at rest
- [x] No encryption in transit
- [x] Publicly accessible cache placement
- [x] Redis auth token not enabled
- [x] Default ports used without hardening

### Redshift Security (5 checks)
- [x] Publicly accessible cluster
- [x] Cluster encryption disabled
- [x] Weak master password policy
- [x] Audit logging disabled
- [x] Enhanced VPC routing disabled

### Cognito Security (5 checks)
- [ ] Weak password/MFA policy
- [ ] User pool encryption not configured
- [ ] Advanced security features disabled
- [ ] Public user pool client without secret
- [ ] Overly permissive CORS

### Backup & Disaster Recovery (5 checks)
- [x] No AWS Backup plan
- [x] Backup vault unencrypted
- [x] No cross-region backup
- [x] Critical resources missing from backup plan
- [x] Backup retention less than 30 days

### Organizations & SCP Expansion (4 checks)
- [x] No SCP protection for root account
- [x] Member account root access not blocked by SCP
- [x] No region restriction guardrails
- [x] AI services unrestricted (Bedrock/SageMaker)

### Network Firewall & Route 53 Security (4 checks)
- [ ] No AWS Network Firewall in high-security VPCs
- [ ] Route 53 Resolver DNS logging disabled
- [ ] DNSSEC not enabled
- [ ] Zone transfer exposure risk

### AppSync Security (4 checks)
- [ ] API key-only authentication
- [ ] Field-level logging disabled
- [ ] Overly permissive resolver behavior
- [ ] No WAF protection

### Glue/Athena Security (3 checks)
- [ ] Glue Data Catalog unencrypted
- [ ] Athena query results unencrypted
- [ ] Overly permissive Data Catalog policy

### Enhanced AI/ML Detection (5 checks)
- [ ] SageMaker notebook public exposure
- [ ] SageMaker jobs outside VPC
- [ ] SageMaker model artifacts unencrypted
- [ ] Bedrock guardrails disabled
- [ ] Unauthorized Bedrock model evaluation jobs

### Compliance & Tagging (3 checks)
- [ ] Untagged critical resources
- [ ] PCI/HIPAA baseline violations
- [ ] Missing cost allocation tags

### Insider Threat Patterns (4 checks)
- [ ] Large-scale S3 data export anomalies
- [ ] After-hours admin activity
- [ ] Database export/snapshot copy to external accounts
- [ ] Mass Secrets Manager secret reads

## Phase 4: Risk Intelligence & Automation 🔲 PLANNED
- [ ] Contextual severity scoring
- [ ] Risk scoring dashboard (account/region)
- [ ] Compliance mapping (CIS, PCI-DSS, SOC 2, HIPAA)
- [ ] Drift detection between scans
- [ ] Auto-remediation templates (Terraform/CloudFormation)
- [ ] Slack/PagerDuty critical alerting

## Phase 5: Enterprise Features 🔲 PLANNED
- [ ] Multi-account Organizations support
- [ ] CI/CD integration
- [ ] SIEM export (Splunk, ELK)
- [ ] Historical trending

---

## Summary

| Phase | Status | Rules |
|-------|--------|-------|
| Phase 1 | ✅ Complete | 73 |
| Phase 2 | 🔲 In Progress | +24 |
| Phase 2.5 | ✅ Complete (Validated) | +10 |
| Phase 3 | 🔲 Planned | +65 |
| Phase 4 | 🔲 Planned | 6 features |
| Phase 5 | 🔲 Planned | 4 features |
