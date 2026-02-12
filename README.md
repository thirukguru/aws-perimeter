# aws-perimeter

<p align="center">
  <a href="https://github.com/thirukguru/aws-perimeter/blob/main/go.mod"><img src="https://img.shields.io/github/go-mod/go-version/thirukguru/aws-perimeter" alt="Go Version"></a>
  <a href="https://pkg.go.dev/github.com/thirukguru/aws-perimeter"><img src="https://pkg.go.dev/badge/github.com/thirukguru/aws-perimeter.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/thirukguru/aws-perimeter"><img src="https://goreportcard.com/badge/github.com/thirukguru/aws-perimeter" alt="Go Report Card"></a>
  <a href="https://github.com/thirukguru/aws-perimeter/blob/main/LICENSE"><img src="https://img.shields.io/github/license/thirukguru/aws-perimeter" alt="License"></a>
</p>

A terminal-based **AWS Security Scanner** with **100+ security checks** across VPC, IAM, S3, CloudTrail, containers (ECS/EKS), and AI attack detection. Detects dangerous IAM permissions, exposed secrets, misconfigured S3 buckets, container vulnerabilities, and emerging LLMjacking threats.

Product overview: [`docs/CAPABILITIES_OVERVIEW.md`](docs/CAPABILITIES_OVERVIEW.md)

## Features

###  VPC Security
- Security group analysis (open SSH/RDP, database ports)
- Public exposure detection & management port risks
- Network ACL analysis & VPC Flow Log audit
- VPC peering risks, bastion host detection
- NAT Gateway status & VPC endpoint coverage

###  IAM Security
- Privilege escalation detection (17 patterns)
- Stale credentials (90+ days)
- Cross-account trust analysis
- MFA enforcement gaps
- Overly permissive policies (`*:*`)
- Role chaining, external ID, permission boundaries

###  S3 Security
- Public bucket detection
- Encryption audit & risky bucket policies
- Public access block status
- Sensitive file/object discovery (`.env`, `.git`, credentials)
- Deep text-content secret detection in S3 objects

###  CloudTrail & Logging
- Trail coverage gaps & multi-region logging
- Log validation status
- CloudWatch Logs integration

### Secrets Detection
- Lambda env vars (10 secret patterns)
- Lambda deployment package (ZIP) scanning
- EC2 user data scanning
- Public S3 object content scanning
- ECR image layer scanning for embedded credentials
- AWS keys, GitHub/Slack/Stripe tokens

###  Container Security (NEW)

#### ECS Security (10 checks)
- Privileged containers
- Secrets in environment variables
- Public IP exposure
- Host network mode
- Non-ECR images
- Writable root filesystem
- Dangerous Linux capabilities
- ECS Exec enabled
- Container Insights status
- Admin task role

#### EKS Security (12 checks)
- Public endpoint access
- Private endpoint disabled
- Control plane logging
- Secrets encryption
- Kubernetes version
- OIDC provider for IRSA
- Legacy auth modes
- Public subnet nodes
- Unrestricted SSH access
- Admin-level node IAM role
- AMI type (Bottlerocket preference)

###  AI Attack Detection (NEW)
*Based on Feb 2025 threat intelligence: 8-minute AWS breach*

- **GPU Instance Monitoring**: Detection of p2/p3/p4/p5, g3/g4/g5, inf1/inf2, trn1 instances
- **GPU Public Exposure**: GPU instances with public IPs
- **GPU IMDSv1 Risk**: GPU instances vulnerable to credential theft
- **Bedrock Abuse**: High-capacity provisioned throughput detection
- **Custom Models**: Unauthorized Bedrock model training
- **Bedrock Logging**: Missing model invocation logging
- **Rapid Provisioning**: EC2 API throttle detection (attack pattern)

## Security Checks Summary

| Category | Count |
|----------|-------|
| Core (IAM, VPC, S3, CloudTrail, Secrets) | 38 |
| Extended (Lambda, ELB, Route53, Inspector, etc.) | 35 |
| Container Security (ECS + EKS) | 22 |
| AI Attack Detection | 7 |
| **Total** | **102** |

## Critical Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Privilege Escalation | 🔴 Critical | User can escalate to admin |
| Admin Access (*:*) | 🔴 Critical | Full AWS access granted |
| Exposed Secrets | 🔴 Critical | API keys/tokens in Lambda/EC2 |
| Public S3 Bucket | 🔴 Critical | Bucket publicly accessible |
| No CloudTrail | 🔴 Critical | No audit logging |
| Open SSH/RDP | 🔴 Critical | Port 22/3389 to internet |
| Privileged Container | 🔴 Critical | ECS container with root access |
| GPU IMDSv1 | 🔴 Critical | GPU instance credentials vulnerable |
| Cross-Account Trust | 🟠 High | External account can assume role |
| EKS Public Endpoint | 🟠 High | Kubernetes API publicly accessible |
| Bedrock No Logging | 🟠 High | AI model usage not audited |

## Prerequisites

### 1. AWS CLI Installed
```bash
# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install
```

### 2. AWS Credentials Configured
```bash
aws configure
# or use named profiles
aws configure --profile myprofile
```

### 3. Required IAM Permissions
Your AWS credentials must have **read-only** access to the services being scanned. The AWS managed policy `ReadOnlyAccess` works, or see [Required Permissions](#required-aws-permissions) below.

> **Note**: aws-perimeter only performs **read operations** and never modifies your AWS resources.

## Installation

### Quick Install (macOS/Linux)
```bash
curl -sSfL https://raw.githubusercontent.com/thirukguru/aws-perimeter/main/install.sh | sh
```

### Using Go
```bash
go install github.com/thirukguru/aws-perimeter@latest
```

## Usage

```bash
aws-perimeter                          # Run full security scan
aws-perimeter --output json            # JSON output
aws-perimeter --profile prod           # Specific AWS profile
aws-perimeter --region us-west-2       # Specific region
aws-perimeter --regions us-east-1,us-west-2            # Multi-region scan
aws-perimeter --regions us-east-1,us-west-2 --max-parallel 4  # Multi-region with controlled concurrency
aws-perimeter --regions us-east-1,us-west-2 --max-parallel 4 --best-effort  # Exit success if at least one region succeeds
aws-perimeter --rules                   # Print RULES.md to stdout (Markdown)
aws-perimeter --capabilities            # Print capabilities overview to stdout (Markdown)
aws-perimeter --all-regions                            # Scan all enabled regions
aws-perimeter --org-scan --org-role-name OrganizationAccountAccessRole  # Multi-account org scan
aws-perimeter --org-scan --max-parallel 5              # Org+region fanout concurrency
aws-perimeter --output html --output-file report.html  # Generate HTML report
aws-perimeter --store --profile prod --region us-west-2 # Run + persist scan
aws-perimeter --trends --trend-days 30 --account-id 123456789012  # Show historical trend table
aws-perimeter history list --db-path ~/.aws-perimeter/history.db
aws-perimeter dashboard --port 8080
```

For fanout modes (`--regions`, `--all-regions`, `--org-scan`) with `--output html --output-file ...`, aws-perimeter writes one report per scan unit with region/account + timestamp suffixes (for example `security-report-us-east-1-20260210-213045.html` or `security-report-123456789012-us-east-1-20260210-213045.html`).
In HTML mode, terminal table output is suppressed and only concise summary lines are printed.

### JSON Automation Mode

When `--output json` is used, `aws-perimeter` emits a single valid JSON document with no banner/spinner noise, so it is safe for pipelines.

```bash
aws-perimeter --profile prod --region us-west-2 --output json | jq .

# Multi-region JSON emits one aggregated top-level JSON document:
aws-perimeter --profile prod --regions us-east-1,us-west-2 --output json | jq .

# export docs via stdout redirection
aws-perimeter --rules > rules.md
aws-perimeter --capabilities > capabilities.md
```

Multi-region JSON payload includes:
- `summary` (`total_regions`, `success`, `failed`, `skipped`)
- `results` (per-region consolidated scan payloads)
- `failures` (region + error details when a region scan fails)

### Fanout Summary Output

For multi-region and org scans in non-JSON output modes, aws-perimeter prints a consolidated summary at the end of execution:

- Per-scan-unit rows with `account_id`, `account_name`, `region`, `status`, `duration`, and `error`.
- Aggregate totals (`TOTAL`, `SUCCESS`, `FAILED`, `SKIPPED`).
- Account-level rollup table for org scans (success/failure/skip counts per account).

### `--max-parallel` and `--best-effort`

- `--max-parallel` controls how many region/account scan units run concurrently in fanout modes (`--regions`, `--all-regions`, `--org-scan`).
- Higher values speed up scans but increase API pressure and chance of throttling/network contention.
- Recommended starting point: `--max-parallel 3` or `--max-parallel 4`.
- `--best-effort` applies to multi-region scans: command exits success (`0`) when at least one region succeeds, even if some regions fail.
- Without `--best-effort`, any failed region returns a non-zero exit code.
- In JSON multi-region output, failed regions appear under `failures` with the exact error.

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--profile` | `-p` | AWS profile to use |
| `--region` | `-r` | AWS region |
| `--regions` | | Comma-separated regions |
| `--all-regions` | | Scan all enabled regions |
| `--org-scan` | | Scan all active AWS Organization accounts |
| `--org-role-name` | | IAM role name to assume in member accounts |
| `--external-id` | | External ID for cross-account assume role |
| `--output` | `-o` | Output format: `table`, `json`, or `html` |
| `--rules` | | Print rules catalog Markdown and exit |
| `--capabilities` | | Print capabilities Markdown and exit |
| `--output-file` | `-f` | Output file (required for html) |
| `--store` | | Persist scan results in SQLite |
| `--db-path` | | Custom SQLite DB path |
| `--trends` | | Show historical trends |
| `--trend-days` | | Trend window in days (default 30) |
| `--compare` | | Compare two recent scans |
| `--export-json` | | Export trends JSON file |
| `--export-csv` | | Export trends CSV file |
| `--account-id` | | Account filter for trends/history |
| `--max-parallel` | | Max concurrent region/account scan units |
| `--best-effort` | | For multi-region scans, return success if at least one region succeeds |
| `--dry-run` | | Remediation preview mode |
| `--remediate` | | Apply supported remediations |
| `--dashboard-port` | | Dashboard port (root flag; dashboard subcommand uses `--port`) |
| `--version` | `-v` | Version information |

## Required AWS Permissions

The following permissions are required for full feature coverage (including multi-region and org scan):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "sts:AssumeRole",
        
        "organizations:DescribeOrganization",
        "organizations:ListAccounts",
        
        "ec2:Describe*",
        "ec2:GetEbsEncryptionByDefault",
        
        "iam:List*",
        "iam:Get*",
        "iam:GenerateCredentialReport",
        
        "s3:ListAllMyBuckets",
        "s3:GetBucket*",
        "s3:GetEncryptionConfiguration",
        
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:LookupEvents",
        
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",
        "lambda:GetFunction",
        
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        
        "ecs:ListClusters",
        "ecs:DescribeClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        
        "eks:ListClusters",
        "eks:DescribeCluster",
        "eks:ListNodegroups",
        "eks:DescribeNodegroup",
        
        "bedrock:ListProvisionedModelThroughputs",
        "bedrock:ListCustomModels",
        "bedrock:GetModelInvocationLoggingConfiguration",
        
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        
        "securityhub:DescribeHub",
        "securityhub:GetFindings",
        
        "config:Describe*",
        
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:Decrypt",
        
        "rds:DescribeDB*",
        
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeContinuousBackups",
        
        "secretsmanager:ListSecrets",
        
        "elasticloadbalancing:Describe*",
        
        "backup:List*",
        
        "apigateway:GET",
        
        "cloudfront:List*",
        "cloudfront:Get*",
        
        "cloudwatch:GetMetricStatistics",
        
        "sns:ListTopics",
        "sqs:ListQueues"
      ],
      "Resource": "*"
    }
  ]
}
```

`kms:Decrypt` is required only when scanning encrypted objects/packages (for example SSE-KMS S3 object reads). Scope this to required KMS keys in production.

For `--org-scan`, the management principal must be allowed to assume a member-account role (default: `OrganizationAccountAccessRole`), for example:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole"
}
```

Member account role trust policy must also allow your scanner principal (user/role) to assume it (and include `sts:ExternalId` condition if you use `--external-id`).

> **Tip**: For a quick start, attach the AWS managed policy `arn:aws:iam::aws:policy/ReadOnlyAccess` to your IAM user/role.

## Roadmap

### Phase 3: Advanced Threat Detection
- [ ] STRIDE threat modeling
- [ ] Attack path analysis
- [ ] Data exfiltration detection
- [ ] Crypto-mining indicators

### Phase 4: Enterprise Features
- [ ] Multi-account Organizations support
- [ ] CI/CD integration
- [ ] SIEM export (Splunk, ELK)
- [ ] Historical trending

---

### Summary

| Phase | Status | Rules |
|-------|--------|-------|
| Phase 1 | ✅ Complete | 73 |
| Phase 2 | 🔲 In Progress | +20 |
| Phase 2.5 | 🆕 AI Attack Detection | +13 |
| Phase 3 | 🔲 Planned | +15 |
| Phase 4 | 🔲 Planned | Features |

## License

Apache License 2.0
