# aws-perimeter

<p align="center">
  <a href="https://github.com/thirukguru/aws-perimeter/blob/main/go.mod"><img src="https://img.shields.io/github/go-mod/go-version/thirukguru/aws-perimeter" alt="Go Version"></a>
  <a href="https://pkg.go.dev/github.com/thirukguru/aws-perimeter"><img src="https://pkg.go.dev/badge/github.com/thirukguru/aws-perimeter.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/thirukguru/aws-perimeter"><img src="https://goreportcard.com/badge/github.com/thirukguru/aws-perimeter" alt="Go Report Card"></a>
  <a href="https://github.com/thirukguru/aws-perimeter/blob/main/LICENSE"><img src="https://img.shields.io/github/license/thirukguru/aws-perimeter" alt="License"></a>
</p>

A terminal-based **AWS Security Scanner** with **102+ security checks** across VPC, IAM, S3, CloudTrail, containers (ECS/EKS), and AI attack detection. Detects dangerous IAM permissions, exposed secrets, misconfigured S3 buckets, container vulnerabilities, and emerging LLMjacking threats.

## Features

### 🔒 VPC Security
- Security group analysis (open SSH/RDP, database ports)
- Public exposure detection & management port risks
- Network ACL analysis & VPC Flow Log audit
- VPC peering risks, bastion host detection
- NAT Gateway status & VPC endpoint coverage

### 🔑 IAM Security
- Privilege escalation detection (17 patterns)
- Stale credentials (90+ days)
- Cross-account trust analysis
- MFA enforcement gaps
- Overly permissive policies (`*:*`)
- Role chaining, external ID, permission boundaries

### 📦 S3 Security
- Public bucket detection
- Encryption audit & risky bucket policies
- Public access block status

### 📋 CloudTrail & Logging
- Trail coverage gaps & multi-region logging
- Log validation status
- CloudWatch Logs integration

### 🔐 Secrets Detection
- Lambda env vars (10 secret patterns)
- EC2 user data scanning
- AWS keys, GitHub/Slack/Stripe tokens

### 🐳 Container Security (NEW)

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

### 🤖 AI Attack Detection (NEW)
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
aws-perimeter --html report.html       # Generate HTML report
```

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--profile` | `-p` | AWS profile to use |
| `--region` | `-r` | AWS region |
| `--output` | `-o` | Output format: `table` or `json` |
| `--html` | | Generate HTML report |
| `--version` | `-v` | Version information |

## Required AWS Permissions

The following read-only permissions are required:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        
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
