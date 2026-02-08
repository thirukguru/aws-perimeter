package htmloutput

// SimpleConverter provides a simplified approach to building HTML report data
// by accepting pre-processed findings rather than raw service types

// ConvertFindingsToReportData converts a list of generic findings into ReportData
func ConvertFindingsToReportData(accountID string, sections []Section) ReportData {
	return ReportData{
		AccountID: accountID,
		Sections:  sections,
	}
}

// NewVPCSection creates a VPC security section
func NewVPCSection(findings []Finding) Section {
	return Section{
		ID:          "vpc-security",
		Title:       "VPC Security",
		Description: "Network security configuration including security groups, NACLs, and flow logs",
		Findings:    findings,
		Status:      sectionStatus(findings),
	}
}

// NewIAMSection creates an IAM security section
func NewIAMSection(findings []Finding) Section {
	return Section{
		ID:          "iam-security",
		Title:       "IAM Security",
		Description: "Identity and Access Management security findings",
		Findings:    findings,
		Status:      sectionStatus(findings),
	}
}

// NewS3Section creates an S3 security section
func NewS3Section(findings []Finding) Section {
	return Section{
		ID:          "s3-security",
		Title:       "S3 Security",
		Description: "S3 bucket security configuration and access controls",
		Findings:    findings,
		Status:      sectionStatus(findings),
	}
}

// NewCloudTrailSection creates a CloudTrail section
func NewCloudTrailSection(findings []Finding) Section {
	return Section{
		ID:          "cloudtrail-security",
		Title:       "CloudTrail",
		Description: "AWS CloudTrail logging and monitoring configuration",
		Findings:    findings,
		Status:      sectionStatus(findings),
	}
}

// NewSecretsSection creates a secrets section
func NewSecretsSection(findings []Finding) Section {
	return Section{
		ID:          "secrets-security",
		Title:       "Secrets & Credentials",
		Description: "Hardcoded secrets and credential exposure detection",
		Findings:    findings,
		Status:      sectionStatus(findings),
	}
}

// NewAdvancedSection creates an advanced security section
func NewAdvancedSection(findings []Finding) Section {
	return Section{
		ID:          "advanced-security",
		Title:       "Security Hub & GuardDuty",
		Description: "AWS native security services status and findings",
		Findings:    findings,
		Status:      sectionStatus(findings),
	}
}

// NewExtendedSection creates an extended security section
func NewExtendedSection(findings []Finding) Section {
	return Section{
		ID:          "extended-security",
		Title:       "Extended Security Checks",
		Description: "VPC endpoints, NAT security, bastion hosts, and IAM advanced analysis",
		Findings:    findings,
		Status:      sectionStatus(findings),
	}
}

func sectionStatus(findings []Finding) string {
	for _, f := range findings {
		if f.Severity == "CRITICAL" {
			return "critical"
		}
	}
	for _, f := range findings {
		if f.Severity == "HIGH" || f.Severity == "MEDIUM" {
			return "warning"
		}
	}
	return "good"
}
