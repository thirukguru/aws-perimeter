// Package compliance provides CIS Benchmark and other compliance framework mappings.
package compliance

// CIS AWS Foundations Benchmark v1.5.0 control mappings
// Each rule maps to one or more CIS control IDs

// CISControl represents a CIS Benchmark control
type CISControl struct {
	ID          string
	Title       string
	Description string
	Framework   string // "CIS", "NIST", "PCI-DSS", etc.
}

// RuleCompliance maps security rules to compliance controls
var RuleCompliance = map[string][]CISControl{
	// VPC Security Rules
	"security_group_open_ssh": {
		{ID: "CIS 5.2", Title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", Framework: "CIS"},
		{ID: "NIST AC-4", Title: "Information Flow Enforcement", Framework: "NIST"},
		{ID: "PCI-DSS 1.3.2", Title: "Limit inbound Internet traffic", Framework: "PCI-DSS"},
	},
	"security_group_open_rdp": {
		{ID: "CIS 5.3", Title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", Framework: "CIS"},
		{ID: "NIST AC-4", Title: "Information Flow Enforcement", Framework: "NIST"},
		{ID: "PCI-DSS 1.3.2", Title: "Limit inbound Internet traffic", Framework: "PCI-DSS"},
	},
	"security_group_open_all": {
		{ID: "CIS 5.4", Title: "Ensure the default security group restricts all traffic", Framework: "CIS"},
		{ID: "NIST AC-4", Title: "Information Flow Enforcement", Framework: "NIST"},
	},
	"vpc_flow_logs_disabled": {
		{ID: "CIS 3.9", Title: "Ensure VPC flow logging is enabled in all VPCs", Framework: "CIS"},
		{ID: "NIST AU-12", Title: "Audit Generation", Framework: "NIST"},
		{ID: "PCI-DSS 10.2", Title: "Implement automated audit trails", Framework: "PCI-DSS"},
	},
	"nacl_overly_permissive": {
		{ID: "CIS 5.1", Title: "Ensure no Network ACLs allow ingress from 0.0.0.0/0", Framework: "CIS"},
	},
	"imdsv1_enabled": {
		{ID: "CIS 5.6", Title: "Ensure EC2 Metadata Service Version 2 is enabled", Framework: "CIS"},
		{ID: "NIST AC-3", Title: "Access Enforcement", Framework: "NIST"},
	},

	// IAM Security Rules
	"root_account_usage": {
		{ID: "CIS 1.7", Title: "Eliminate use of the root user for administrative and daily tasks", Framework: "CIS"},
		{ID: "NIST AC-6", Title: "Least Privilege", Framework: "NIST"},
		{ID: "PCI-DSS 8.1.1", Title: "Define and implement policies for user identification", Framework: "PCI-DSS"},
	},
	"root_mfa_disabled": {
		{ID: "CIS 1.5", Title: "Ensure MFA is enabled for the root user account", Framework: "CIS"},
		{ID: "NIST IA-2", Title: "Identification and Authentication", Framework: "NIST"},
		{ID: "PCI-DSS 8.3", Title: "Incorporate two-factor authentication", Framework: "PCI-DSS"},
	},
	"user_mfa_disabled": {
		{ID: "CIS 1.10", Title: "Ensure multi-factor authentication is enabled for all IAM users", Framework: "CIS"},
		{ID: "NIST IA-2", Title: "Identification and Authentication", Framework: "NIST"},
		{ID: "PCI-DSS 8.3", Title: "Incorporate two-factor authentication", Framework: "PCI-DSS"},
	},
	"stale_access_keys": {
		{ID: "CIS 1.14", Title: "Ensure access keys are rotated every 90 days or less", Framework: "CIS"},
		{ID: "NIST IA-5", Title: "Authenticator Management", Framework: "NIST"},
		{ID: "PCI-DSS 8.2.4", Title: "Change user passwords at least once every 90 days", Framework: "PCI-DSS"},
	},
	"unused_credentials": {
		{ID: "CIS 1.12", Title: "Ensure credentials unused for 45 days or greater are disabled", Framework: "CIS"},
		{ID: "NIST AC-2", Title: "Account Management", Framework: "NIST"},
	},
	"overly_permissive_policy": {
		{ID: "CIS 1.16", Title: "Ensure IAM policies with full *:* administrative privileges are not attached", Framework: "CIS"},
		{ID: "NIST AC-6", Title: "Least Privilege", Framework: "NIST"},
		{ID: "PCI-DSS 7.1.2", Title: "Restrict access to privileged user IDs", Framework: "PCI-DSS"},
	},
	"cross_account_trust": {
		{ID: "CIS 1.17", Title: "Ensure IAM roles allow only trusted principals", Framework: "CIS"},
		{ID: "NIST AC-3", Title: "Access Enforcement", Framework: "NIST"},
	},
	"missing_permission_boundary": {
		{ID: "CIS 1.18", Title: "Ensure IAM permission boundaries are applied", Framework: "CIS"},
		{ID: "NIST AC-6", Title: "Least Privilege", Framework: "NIST"},
	},
	"privilege_escalation": {
		{ID: "CIS 1.16", Title: "Ensure no IAM policies allow privilege escalation", Framework: "CIS"},
		{ID: "NIST AC-6", Title: "Least Privilege", Framework: "NIST"},
	},

	// S3 Security Rules
	"s3_public_access": {
		{ID: "CIS 2.1.1", Title: "Ensure S3 Bucket Policy is set to deny HTTP requests", Framework: "CIS"},
		{ID: "CIS 2.1.2", Title: "Ensure S3 bucket public access is not granted", Framework: "CIS"},
		{ID: "NIST AC-3", Title: "Access Enforcement", Framework: "NIST"},
		{ID: "PCI-DSS 7.1", Title: "Limit access to system components", Framework: "PCI-DSS"},
	},
	"s3_encryption_disabled": {
		{ID: "CIS 2.1.1", Title: "Ensure all S3 buckets employ encryption-at-rest", Framework: "CIS"},
		{ID: "NIST SC-28", Title: "Protection of Information at Rest", Framework: "NIST"},
		{ID: "PCI-DSS 3.4", Title: "Render PAN unreadable anywhere it is stored", Framework: "PCI-DSS"},
	},
	"s3_risky_policy": {
		{ID: "CIS 2.1.5", Title: "Ensure S3 bucket policies do not allow public access", Framework: "CIS"},
		{ID: "NIST AC-3", Title: "Access Enforcement", Framework: "NIST"},
	},
	"s3_versioning_disabled": {
		{ID: "CIS 2.1.3", Title: "Ensure S3 Buckets have versioning enabled", Framework: "CIS"},
		{ID: "NIST CP-9", Title: "Information System Backup", Framework: "NIST"},
	},

	// CloudTrail Rules
	"cloudtrail_disabled": {
		{ID: "CIS 3.1", Title: "Ensure CloudTrail is enabled in all regions", Framework: "CIS"},
		{ID: "NIST AU-2", Title: "Audit Events", Framework: "NIST"},
		{ID: "PCI-DSS 10.1", Title: "Implement audit trails to link all access to individual users", Framework: "PCI-DSS"},
	},
	"cloudtrail_no_log_validation": {
		{ID: "CIS 3.2", Title: "Ensure CloudTrail log file validation is enabled", Framework: "CIS"},
		{ID: "NIST AU-9", Title: "Protection of Audit Information", Framework: "NIST"},
	},
	"cloudtrail_not_encrypted": {
		{ID: "CIS 3.5", Title: "Ensure CloudTrail logs are encrypted at rest using KMS CMKs", Framework: "CIS"},
		{ID: "NIST SC-28", Title: "Protection of Information at Rest", Framework: "NIST"},
	},
	"cloudtrail_no_cloudwatch": {
		{ID: "CIS 3.4", Title: "Ensure CloudTrail trails are integrated with CloudWatch Logs", Framework: "CIS"},
		{ID: "NIST AU-6", Title: "Audit Review, Analysis, and Reporting", Framework: "NIST"},
	},

	// KMS Rules
	"kms_key_rotation_disabled": {
		{ID: "CIS 3.6", Title: "Ensure rotation for customer-created CMKs is enabled", Framework: "CIS"},
		{ID: "NIST SC-12", Title: "Cryptographic Key Establishment and Management", Framework: "NIST"},
		{ID: "PCI-DSS 3.6", Title: "Key management procedures", Framework: "PCI-DSS"},
	},

	// RDS Rules
	"rds_public_access": {
		{ID: "CIS 2.3.1", Title: "Ensure RDS instances are not publicly accessible", Framework: "CIS"},
		{ID: "NIST AC-4", Title: "Information Flow Enforcement", Framework: "NIST"},
		{ID: "PCI-DSS 1.3", Title: "Prohibit direct public access between the Internet and any system component", Framework: "PCI-DSS"},
	},
	"rds_encryption_disabled": {
		{ID: "CIS 2.3.1", Title: "Ensure RDS encryption is enabled", Framework: "CIS"},
		{ID: "NIST SC-28", Title: "Protection of Information at Rest", Framework: "NIST"},
		{ID: "PCI-DSS 3.4", Title: "Render PAN unreadable anywhere it is stored", Framework: "PCI-DSS"},
	},
	"rds_backup_disabled": {
		{ID: "CIS 2.3.2", Title: "Ensure RDS automated backups are enabled", Framework: "CIS"},
		{ID: "NIST CP-9", Title: "Information System Backup", Framework: "NIST"},
	},

	// EBS Rules
	"ebs_encryption_disabled": {
		{ID: "CIS 2.2.1", Title: "Ensure EBS volume encryption is enabled", Framework: "CIS"},
		{ID: "NIST SC-28", Title: "Protection of Information at Rest", Framework: "NIST"},
		{ID: "PCI-DSS 3.4", Title: "Render PAN unreadable anywhere it is stored", Framework: "PCI-DSS"},
	},
	"ebs_snapshot_public": {
		{ID: "CIS 2.2.2", Title: "Ensure EBS snapshots are not publicly restorable", Framework: "CIS"},
		{ID: "NIST AC-3", Title: "Access Enforcement", Framework: "NIST"},
	},

	// Lambda Rules
	"lambda_public_access": {
		{ID: "CIS 2.5.1", Title: "Ensure Lambda functions are not publicly accessible", Framework: "CIS"},
		{ID: "NIST AC-3", Title: "Access Enforcement", Framework: "NIST"},
	},
	"lambda_vpc_not_configured": {
		{ID: "CIS 2.5.2", Title: "Ensure Lambda functions are configured with VPC", Framework: "CIS"},
		{ID: "NIST AC-4", Title: "Information Flow Enforcement", Framework: "NIST"},
	},

	// GuardDuty Rules
	"guardduty_disabled": {
		{ID: "CIS 4.1", Title: "Ensure GuardDuty is enabled", Framework: "CIS"},
		{ID: "NIST SI-4", Title: "Information System Monitoring", Framework: "NIST"},
	},

	// Security Hub Rules
	"securityhub_disabled": {
		{ID: "CIS 4.2", Title: "Ensure Security Hub is enabled", Framework: "CIS"},
		{ID: "NIST SI-4", Title: "Information System Monitoring", Framework: "NIST"},
	},

	// Config Rules
	"config_disabled": {
		{ID: "CIS 3.8", Title: "Ensure AWS Config is enabled in all regions", Framework: "CIS"},
		{ID: "NIST CM-8", Title: "Information System Component Inventory", Framework: "NIST"},
	},

	// Secrets Detection
	"hardcoded_secrets": {
		{ID: "CIS 1.20", Title: "Ensure secrets are not stored in code or environment variables", Framework: "CIS"},
		{ID: "NIST IA-5", Title: "Authenticator Management", Framework: "NIST"},
		{ID: "PCI-DSS 6.3.1", Title: "Develop applications based on secure coding guidelines", Framework: "PCI-DSS"},
	},
}

// GetComplianceIDs returns a list of compliance IDs for a given rule type
func GetComplianceIDs(ruleType string) []string {
	controls, ok := RuleCompliance[ruleType]
	if !ok {
		return nil
	}

	ids := make([]string, 0, len(controls))
	for _, c := range controls {
		ids = append(ids, c.ID)
	}
	return ids
}

// GetCISControls returns only CIS controls for a given rule type
func GetCISControls(ruleType string) []string {
	controls, ok := RuleCompliance[ruleType]
	if !ok {
		return nil
	}

	ids := make([]string, 0)
	for _, c := range controls {
		if c.Framework == "CIS" {
			ids = append(ids, c.ID)
		}
	}
	return ids
}
