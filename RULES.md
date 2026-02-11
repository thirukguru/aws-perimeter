# AWS Perimeter Security Rules

**All rules implemented are production-ready** and based on real-world AWS security best practices, AWS threat intelligence, and industry-standard security frameworks.

---

## 🚀 Execution Modes

| Mode | Description |
|------|-------------|
| **Single Region** | Run against one region using `--region` (or SDK/default region resolution) |
| **Multi Region** | Run the same rule set across multiple regions with `--regions` or `--all-regions`; emits consolidated end-of-run fanout summary |
| **Multi Account (Org)** | Scan active AWS Organizations accounts with `--org-scan` using per-account role assumption; includes account-level rollup summary |
| **Historical Storage** | Persist findings/lifecycle in SQLite with `--store` and review using `--trends` / `history` commands |
| **Dashboard/API** | Local dashboard and APIs (`dashboard`, `/api/trends`, `/api/scans`, `/api/findings`) built from stored scan history |

---

## 🔒 VPC Security (10 Rules)

| Rule | Description |
|------|-------------|
| **Security Group Risks** | Detects overly permissive security groups with 0.0.0.0/0 access on risky ports (SSH, RDP, DB) |
| **Unused Security Groups** | Identifies security groups not attached to any resources (cleanup candidates) |
| **Public Exposure** | Finds EC2 instances with public IPs and open ports exposed to the internet |
| **NACL Risks** | Detects Network ACLs with overly permissive allow-all rules |
| **VPC Flow Logs** | Checks if VPC flow logs are enabled for network traffic monitoring |
| **Management Port Exposure** | Finds management ports (SSH/RDP/admin) exposed to internet - based on GRU Sandworm campaign |
| **Plaintext Protocols** | Detects unencrypted protocols (Telnet, FTP, HTTP) allowed - credential harvesting risk |
| **IMDSv1 Enabled** | Finds EC2 instances using IMDSv1 which enables SSRF credential theft attacks |
| **Network Appliance Risks** | Detects exposed VPN/firewall appliances (Cisco, Palo Alto, etc.) - nation-state targets |
| **Management Subnet Risks** | Identifies management interfaces in public subnets |

---

## 👤 IAM Security (8 Rules)

| Rule | Description |
|------|-------------|
| **Privilege Escalation** | Detects IAM policies that allow privilege escalation paths (CreateAccessKey, PassRole, etc.) |
| **Users Without MFA** | Finds console users without multi-factor authentication enabled |
| **Stale Credentials** | Identifies access keys and passwords not used or rotated in 90+ days |
| **Cross-Account Trusts** | Analyzes role trust policies for external account access and wildcard principals |
| **Overly Permissive Policies** | Detects policies with dangerous permissions (*, admin access) |
| **Missing Permission Boundaries** | Finds privileged principals without permission boundaries |
| **Unused Admin Roles** | Identifies admin roles not used recently - targets for credential abuse |
| **Quarantined Users** | Detects users that appear quarantined (indicators of past compromise) |

---

## 📦 S3 Security (4 Rules)

| Rule | Description |
|------|-------------|
| **Public Buckets** | Detects buckets with public access enabled or public ACLs |
| **Unencrypted Buckets** | Finds buckets without default encryption configured |
| **Risky Bucket Policies** | Analyzes policies for overly permissive access (Principal: *, Action: *) |
| **Sensitive File Exposure** | Scans for exposed sensitive files (.env, .git, credentials) - based on EmeraldWhale campaign |

---

## 📋 CloudTrail Security (3 Rules)

| Rule | Description |
|------|-------------|
| **Recent Role Creations** | Monitors for IAM role creation - attackers create backdoor roles for persistence |
| **Suspicious API Activity** | Detects unusual API patterns indicating potential compromise |
| **Root Account Usage** | Alerts on any root account API activity - should use IAM users/roles |

---

## 🔑 Secrets Detection (5 Rules)

| Rule | Description |
|------|-------------|
| **Lambda Environment Variables** | Scans Lambda env vars for hardcoded secrets (AWS keys, API keys, tokens) |
| **Lambda Code Package Secrets** | Scans Lambda deployment package contents (ZIP) for embedded secrets and private keys |
| **EC2 User Data** | Checks EC2 instance user data for embedded credentials |
| **Public S3 Objects** | Scans text files and object content in public buckets for exposed secrets |
| **ECR Layer Secrets** | Scans ECR image layers (tar/gzip) for embedded secrets in text-like files |

---

## 🛡️ Advanced Security Services (4 Rules)

| Rule | Description |
|------|-------------|
| **Security Hub Status** | Checks if AWS Security Hub is enabled for centralized findings |
| **Security Hub Findings** | Reports critical/high Security Hub findings |
| **GuardDuty Status** | Checks if GuardDuty is enabled for threat detection |
| **GuardDuty Findings** | Reports active GuardDuty threat findings |

---

## 🌐 CloudFront Security (6 Rules) - NEW

| Rule | Description |
|------|-------------|
| **HTTP Traffic Allowed** | Detects distributions allowing unencrypted HTTP traffic |
| **Weak TLS Version** | Finds distributions using TLS < 1.2 |
| **No WAF Association** | CloudFront not protected by AWS WAF |
| **Access Logging Disabled** | No access logs for security monitoring |
| **HTTP to Origin** | Insecure origin protocol configuration |
| **No Geo-Restriction** | No geographic restrictions configured |

---

## 🚪 API Gateway Security (10 Rules) - NEW

| Rule | Description |
|------|-------------|
| **No Authorization (REST)** | REST API methods without authentication |
| **No Authorization (HTTP)** | HTTP API routes without authentication |
| **No WAF** | API Gateway not protected by WAF |
| **No Access Logging** | Access logging disabled |
| **Permissive Policy** | Resource policy with Principal: * |
| **CORS Wildcard** | Allows requests from all origins |
| **No Throttling** | No rate limiting configured |
| **No Client Certificate** | Missing mTLS for backend |
| **No API Key** | Sensitive endpoints without API key |
| **No X-Ray Tracing** | Observability disabled |

---

## 🗄️ Aurora/RDS Security (10 Rules) - NEW

| Rule | Description |
|------|-------------|
| **No Encryption** | Database not encrypted at rest |
| **Publicly Accessible** | Database accessible from internet |
| **Low Backup Retention** | Backup retention < 7 days |
| **No Deletion Protection** | Deletion protection disabled |
| **No IAM Authentication** | Using password-only auth |
| **Single Instance** | No Multi-AZ deployment |
| **No Auto Upgrade** | Minor version auto-upgrade disabled |
| **No Performance Insights** | Performance monitoring disabled |
| **No Log Export** | CloudWatch log export disabled |
| **No Copy Tags** | Tags not copied to snapshots |

---

## 🐳 ECS Security (10 Rules) - NEW

| Rule | Description |
|------|-------------|
| **Privileged Container** | Container runs in privileged mode |
| **Run As Root** | Container runs as root user |
| **Hardcoded Secrets** | Secrets in environment variables |
| **Public IP Assigned** | Task has public IP exposure |
| **Host Network Mode** | Container shares host network |
| **Public Image** | Non-ECR container image |
| **Writable Root FS** | Root filesystem not read-only |
| **Dangerous Capability** | SYS_ADMIN/NET_ADMIN added |
| **ECS Exec Enabled** | Shell access to containers |
| **No Container Insights** | Monitoring not enabled |

---

## ☸️ EKS Security (12 Rules) - NEW

| Rule | Description |
|------|-------------|
| **Public Endpoint Open** | API server exposed to 0.0.0.0/0 |
| **No Private Endpoint** | No private API access |
| **No Control Plane Logs** | CloudWatch logging disabled |
| **Incomplete Logging** | Missing api/audit/auth logs |
| **Secrets Not Encrypted** | No KMS encryption for secrets |
| **Outdated K8s Version** | Version < 1.28 |
| **No OIDC Provider** | IRSA not configured |
| **Legacy Auth Mode** | Using aws-auth ConfigMap |
| **Public Subnet Nodes** | Workers in public subnets |
| **Unrestricted SSH** | No SG restriction on SSH |
| **Admin Node Role** | Nodes have admin IAM |
| **Standard AMI** | Not using Bottlerocket |

---

## 🔧 Extended Checks (15 Rules)

| Rule | Description |
|------|-------------|
| **ALB Security** | Detects ALBs without WAF, HTTPS, or access logs |
| **ALB Listener Risks** | Finds HTTP listeners without redirect to HTTPS |
| **Lambda Permissive Roles** | Identifies Lambda functions with overly broad IAM permissions |
| **AWS Config Status** | Checks if AWS Config is enabled for compliance tracking |
| **EBS Default Encryption** | Verifies EBS default encryption is enabled |
| **KMS Key Rotation** | Ensures customer-managed KMS keys have rotation enabled |
| **RDS Security** | Detects public RDS, unencrypted databases, missing backups |
| **DynamoDB Protection** | Checks for PITR and deletion protection settings |
| **Secret Rotation** | Identifies Secrets Manager secrets without rotation |
| **VPC Endpoint Risks** | Analyzes VPC endpoint policies for overly permissive access |
| **NAT Gateway HA** | Detects single-AZ NAT Gateway configurations |
| **VPC Peering Risks** | Analyzes VPC peering for security concerns |
| **Bastion Hosts** | Detects bastion/jump hosts in the environment |
| **Role Chain Risks** | Identifies IAM role assumption chains that could be abused |
| **External ID Missing** | Finds cross-account roles without external ID requirement |

---

## 🤖 AI Attack Detection (10 Rules)

*Based on Feb 2025 threat intelligence: 8-minute AWS breach using AI*

| Rule | Severity | Description |
|------|----------|-------------|
| **GPU Instance Running** | Medium/High | Detects p2/p3/p4/p5, g3/g4/g5, inf, trn instances - LLMjacking targets |
| **GPU Public IP** | High | GPU instance with public IP - easily discoverable target |
| **GPU IMDSv1** | Critical | GPU instance using IMDSv1 - credentials easily stolen |
| **High Bedrock Capacity** | Medium | Provisioned throughput with high model units |
| **Custom Bedrock Model** | Medium | Unauthorized custom model training detected |
| **No Bedrock Logging** | High | Model invocation logging disabled - abuse goes undetected |
| **Rapid API Activity** | High | EC2 API throttling - indicates automated attack patterns |
| **Lateral Movement** | High | >5 role assumptions in 1 hour - cross-service movement |
| **Rapid Admin Access** | Critical | Multiple admin IAM actions in 15 min - privilege escalation |
| **CloudTrail Gaps** | Critical | StopLogging/DeleteTrail/UpdateTrail - covering tracks |

---

## 📨 SNS/SQS Security (5 Rules) - NEW

| Rule | Description |
|------|-------------|
| **Public SNS Topics** | Detects SNS topics with resource policies allowing public principals (`Principal: "*"`) |
| **Unencrypted SNS Topics** | Finds SNS topics without KMS encryption configured |
| **Public SQS Queues** | Detects SQS queues with resource policies allowing public principals |
| **Unencrypted SQS Queues** | Identifies SQS queues without SSE-SQS or SSE-KMS encryption enabled |
| **Missing SQS DLQ** | Flags SQS queues with no dead-letter queue (RedrivePolicy) configured |

---

## 🐳 ECR Security (8 Rules) - NEW

| Rule | Description |
|------|-------------|
| **Mutable Image Tags** | Detects repositories where image tag mutability is set to `MUTABLE` |
| **No Image Scanning** | Identifies repositories with scan-on-push disabled |
| **Public ECR Repository** | Detects repositories with policies allowing public principals |
| **No KMS Encryption** | Flags repositories not configured with KMS encryption |
| **No Lifecycle Policy** | Finds repositories without lifecycle retention policy |
| **Cross-Account Pull Policy** | Flags repositories allowing `ecr:BatchGetImage` for wildcard principals or external account principals |
| **Image Tag Immutability Bypass Risk** | Flags repositories with mutable tags (tag immutability disabled), enabling tag overwrite attacks |
| **No Vulnerability Suppression Policy** | Flags repositories without Inspector suppression/exception filter governance for vulnerability findings |

---

## 💾 Backup & Disaster Recovery (5 Rules) - NEW

| Rule | Description |
|------|-------------|
| **No AWS Backup Plan** | Detects accounts with no AWS Backup plans configured |
| **Backup Vault Unencrypted** | Flags backup vaults without KMS key configuration |
| **No Cross-Region Backup** | Detects backup plans without cross-region copy actions |
| **Critical Resources Not Protected** | Flags missing protected resource coverage for critical classes (EC2/RDS/EFS) |
| **Short Backup Retention** | Identifies backup lifecycle retention configured for less than 30 days |

---

## 🏛️ Organizations & SCP Expansion (4 Rules) - NEW

| Rule | Description |
|------|-------------|
| **No SCP Protection at Root** | Detects organizations where no SCP is attached to the root target |
| **Root Access Not Blocked in Members** | Flags missing SCP deny patterns to restrict root-user sensitive actions |
| **No Region Restriction Guardrails** | Detects missing `aws:RequestedRegion` deny guardrails in SCPs |
| **AI Services Unrestricted** | Flags missing SCP restrictions for Bedrock/SageMaker actions |

---

## λ Lambda Security Expansion (6 Rules) - NEW

| Rule | Description |
|------|-------------|
| **VPC Lambda Without Egress** | Detects Lambda functions in VPC subnets with no NAT route or VPC endpoint coverage |
| **Untrusted Lambda Layers** | Flags Lambda layers outside approved/AWS-managed publishers |
| **Reserved Concurrency Set to 0** | Identifies functions effectively disabled by hard concurrency limit |
| **SnapStart With Secret-like Env Keys** | Detects SnapStart-enabled functions that include secret-like environment variable keys |
| **Function URL Without Auth** | Flags Function URLs configured with `AuthType=NONE` |
| **Ephemeral Storage Encryption Not Enforced** | Flags functions using expanded ephemeral `/tmp` storage (>512 MB) without configured `KMSKeyArn` |

---

## 🧭 EventBridge/Step Functions Security (3 Rules) - NEW

| Rule | Description |
|------|-------------|
| **Open EventBridge Bus** | Detects custom EventBridge buses with policies that allow public principals |
| **Step Function Logging Disabled** | Flags state machines without CloudWatch logging (or logging level set to `OFF`) |
| **State Machine Public Exposure** | Flags Express workflows whose execution role trust policy allows wildcard principals |

---

## 🧠 ElastiCache/MemoryDB Security (5 Rules) - NEW

| Rule | Description |
|------|-------------|
| **No Encryption at Rest** | Detects cache resources without at-rest encryption hardening (including missing CMK governance for MemoryDB) |
| **No Encryption in Transit** | Flags clusters where TLS/transit encryption is disabled |
| **Publicly Accessible Cache Placement** | Detects cache subnet groups mapped to subnets with public IP assignment enabled |
| **Redis Auth Not Enforced** | Flags Redis/Valkey resources without auth token (or MemoryDB open-access ACL) |
| **Default Port Used** | Detects default Redis/Memcached ports (6379/11211) in use |

---

## 🏭 Redshift Security (5 Rules) - NEW

| Rule | Description |
|------|-------------|
| **Publicly Accessible Cluster** | Detects Redshift clusters exposed via public networking |
| **Cluster Encryption Disabled** | Flags Redshift clusters without encryption at rest |
| **Weak Master Password Policy** | Flags clusters not using managed admin credentials secret for stronger credential governance |
| **Audit Logging Disabled** | Detects clusters without Redshift audit logging enabled |
| **Enhanced VPC Routing Disabled** | Flags clusters where enhanced VPC routing is not enabled |

---

## 🪪 Cognito Security (5 Rules) - NEW

| Rule | Description |
|------|-------------|
| **Weak Password/MFA Policy** | Detects weak user pool password policy settings or MFA disabled (`MfaConfiguration=OFF`) |
| **User Pool Encryption Not Configured** | Flags user pools without configured customer-managed KMS integration where supported |
| **Advanced Security Features Disabled** | Detects user pools where advanced security mode is not enforced |
| **Public User Pool Client Without Secret** | Flags OAuth/auth-enabled app clients that do not use a client secret |
| **Overly Permissive CORS** | Detects wildcard or non-HTTPS callback/logout URL configuration (except localhost dev patterns) |

---

## 📊 Summary

| Category | Rule Count | Production Ready |
|----------|------------|------------------|
| VPC Security | 10 | ✅ |
| IAM Security | 8 | ✅ |
| S3 Security | 4 | ✅ |
| CloudTrail | 3 | ✅ |
| Secrets | 5 | ✅ |
| Advanced | 4 | ✅ |
| CloudFront | 6 | ✅ |
| API Gateway | 10 | ✅ |
| Aurora/RDS | 10 | ✅ |
| ECS Security | 10 | ✅ |
| EKS Security | 12 | ✅ |
| Extended | 15 | ✅ |
| AI Attack Detection | 10 | ✅ |
| SNS/SQS Security | 5 | ✅ |
| ECR Security | 8 | ✅ |
| Backup & DR Security | 5 | ✅ |
| Organizations & SCP Expansion | 4 | ✅ |
| Lambda Security Expansion | 6 | ✅ |
| EventBridge/Step Functions Security | 3 | ✅ |
| ElastiCache/MemoryDB Security | 5 | ✅ |
| Redshift Security | 5 | ✅ |
| Cognito Security | 5 | ✅ |
| **Total** | **153** | ✅ |

---

## 🔗 Threat Intelligence References

Many rules are based on real-world attack patterns:
- **GRU Sandworm Campaign** - Network edge device targeting
- **EmeraldWhale Campaign** - S3 bucket credential harvesting
- **ShinyHunters/Nemesis** - IAM privilege escalation patterns
- **Feb 2025 LLMjacking** - 8-minute AWS breach using AI for credential theft
- **AWS Security Best Practices** - CIS Benchmarks, AWS Well-Architected Framework
