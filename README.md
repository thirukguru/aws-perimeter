# aws-perimeter

<p align="center">
  <a href="https://github.com/thirukguru/aws-perimeter/blob/main/go.mod"><img src="https://img.shields.io/github/go-mod/go-version/thirukguru/aws-perimeter" alt="Go Version"></a>
  <a href="https://pkg.go.dev/github.com/thirukguru/aws-perimeter"><img src="https://pkg.go.dev/badge/github.com/thirukguru/aws-perimeter.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/thirukguru/aws-perimeter"><img src="https://goreportcard.com/badge/github.com/thirukguru/aws-perimeter" alt="Go Report Card"></a>
  <a href="https://github.com/thirukguru/aws-perimeter/blob/main/LICENSE"><img src="https://img.shields.io/github/license/thirukguru/aws-perimeter" alt="License"></a>
</p>

A terminal-based **AWS Security Scanner** that analyzes your cloud infrastructure for security misconfigurations. Detects dangerous IAM permissions, exposed secrets, misconfigured S3 buckets, and logging gaps.

## Features

### 🔐 VPC Security
- Security group analysis (open SSH/RDP, database ports)
- Public exposure detection
- Network ACL analysis
- VPC Flow Log audit

### 🔑 IAM Security
- Privilege escalation detection (17 patterns)
- Stale credentials (90+ days)
- Cross-account trust analysis
- MFA enforcement gaps
- Overly permissive policies (`*:*`)

### 🪣 S3 Security
- Public bucket detection
- Encryption audit
- Risky bucket policies

### 📋 CloudTrail Audit
- Trail coverage gaps
- Multi-region logging
- Log validation status

### 🔐 Secrets Detection
- Lambda env vars (10 secret patterns)
- EC2 user data scanning
- AWS keys, GitHub/Slack/Stripe tokens

## Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Privilege Escalation | 🔴 Critical | User can escalate to admin |
| Admin Access (*:*) | 🔴 Critical | Full AWS access granted |
| Exposed Secrets | 🔴 Critical | API keys/tokens in Lambda/EC2 |
| Public S3 Bucket | 🔴 Critical | Bucket publicly accessible |
| No CloudTrail | 🔴 Critical | No audit logging |
| Open SSH/RDP | 🔴 Critical | Port 22/3389 to internet |
| Cross-Account Trust | 🟠 High | External account can assume role |
| Stale Access Keys | 🟠 High | Keys not rotated in 90+ days |
| No Encryption | 🟡 Medium | S3 bucket unencrypted |
| No MFA | 🟡 Medium | Console user without MFA |

## Prerequisites

Before using aws-perimeter, ensure you have:

### 1. AWS CLI Installed
```bash
# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# Windows
# Download: https://awscli.amazonaws.com/AWSCLIV2.msi
```

### 2. AWS Credentials Configured
```bash
aws configure
# AWS Access Key ID: AKIA...
# AWS Secret Access Key: ****
# Default region name: us-east-1
# Default output format: json
```

Or use named profiles:
```bash
aws configure --profile myprofile
```

### 3. Required IAM Permissions
Your AWS credentials must have **read-only** access to the services being scanned. See [Required AWS Permissions](#required-aws-permissions) below.

> **Note**: aws-perimeter only performs **read operations** and never modifies your AWS resources.

---

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
aws-perimeter                      # Run full security scan
aws-perimeter --output json        # JSON output
aws-perimeter --profile prod       # Specific AWS profile
aws-perimeter --region us-west-2   # Specific region
```

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--profile` | `-p` | AWS profile to use |
| `--region` | `-r` | AWS region |
| `--output` | `-o` | Output format: `table` or `json` |
| `--version` | `-v` | Version information |

## Required AWS Permissions

The following read-only permissions are required. You can use the AWS managed policy `ReadOnlyAccess` or create a custom policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",

        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeSnapshots",
        "ec2:DescribeImages",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:GetEbsDefaultKmsKeyId",

        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetRole",
        "iam:ListMFADevices",
        "iam:ListInstanceProfiles",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport",

        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:ListBucket",
        "s3:GetObject",

        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:LookupEvents",

        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",

        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "guardduty:GetFindings",

        "securityhub:DescribeHub",
        "securityhub:GetFindings",

        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels",

        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",

        "rds:DescribeDBInstances",

        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeContinuousBackups",

        "secretsmanager:ListSecrets",

        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",

        "backup:ListBackupVaults",
        "backup:ListBackupPlans",
        "backup:ListProtectedResources",

        "apigateway:GET",

        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution",

        "rds:DescribeDBClusters",
        "rds:DescribeDBInstances",
        "SNS:ListTopics",
        "ec2:DescribeNetworkInterfaces",
        "sqs:listqueues"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Tip**: For a quick start, attach the AWS managed policy `arn:aws:iam::aws:policy/ReadOnlyAccess` to your IAM user/role.

## License

Apache License 2.0
