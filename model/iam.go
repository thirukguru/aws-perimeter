package model

import "github.com/thirukguru/aws-perimeter/service/iam"

// RenderIAMInput contains all IAM security findings for rendering
type RenderIAMInput struct {
	AccountID                string
	PrivilegeEscalation      []iam.PrivEscRisk
	StaleCredentials         []iam.StaleCredential
	CrossAccountTrusts       []iam.CrossAccountTrust
	UsersWithoutMFA          []iam.UserMFAStatus
	OverlyPermissivePolicies []iam.DangerousPolicy
	MissingBoundaries        []iam.PermissionBoundary
}

// IAMReportJSON represents the JSON output for IAM security report
type IAMReportJSON struct {
	AccountID                string                  `json:"account_id"`
	GeneratedAt              string                  `json:"generated_at"`
	HasFindings              bool                    `json:"has_findings"`
	Summary                  IAMSummaryJSON          `json:"summary"`
	PrivilegeEscalation      []PrivEscRiskJSON       `json:"privilege_escalation_risks"`
	StaleCredentials         []StaleCredentialJSON   `json:"stale_credentials"`
	CrossAccountTrusts       []CrossAccountTrustJSON `json:"cross_account_trusts"`
	UsersWithoutMFA          []UserMFAStatusJSON     `json:"users_without_mfa"`
	OverlyPermissivePolicies []DangerousPolicyJSON   `json:"overly_permissive_policies"`
}

// IAMSummaryJSON summarizes IAM findings by severity
type IAMSummaryJSON struct {
	TotalFindings int `json:"total_findings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
}

// PrivEscRiskJSON represents a privilege escalation risk in JSON
type PrivEscRiskJSON struct {
	PrincipalType    string   `json:"principal_type"`
	PrincipalName    string   `json:"principal_name"`
	PrincipalARN     string   `json:"principal_arn"`
	EscalationPath   string   `json:"escalation_path"`
	DangerousActions []string `json:"dangerous_actions"`
	Severity         string   `json:"severity"`
	Recommendation   string   `json:"recommendation"`
}

// StaleCredentialJSON represents a stale credential in JSON
type StaleCredentialJSON struct {
	UserName          string `json:"user_name"`
	CredentialType    string `json:"credential_type"`
	AccessKeyID       string `json:"access_key_id,omitempty"`
	CreatedDate       string `json:"created_date"`
	LastUsedDate      string `json:"last_used_date"`
	DaysSinceLastUse  int    `json:"days_since_last_use"`
	DaysSinceCreation int    `json:"days_since_creation"`
	Severity          string `json:"severity"`
	Recommendation    string `json:"recommendation"`
}

// CrossAccountTrustJSON represents a cross-account trust in JSON
type CrossAccountTrustJSON struct {
	RoleName           string `json:"role_name"`
	RoleARN            string `json:"role_arn"`
	TrustedAccountID   string `json:"trusted_account_id,omitempty"`
	TrustedPrincipal   string `json:"trusted_principal"`
	IsExternalAccount  bool   `json:"is_external_account"`
	AllowsAnyPrincipal bool   `json:"allows_any_principal"`
	Severity           string `json:"severity"`
	Description        string `json:"description"`
	Recommendation     string `json:"recommendation"`
}

// UserMFAStatusJSON represents MFA status in JSON
type UserMFAStatusJSON struct {
	UserName       string `json:"user_name"`
	UserARN        string `json:"user_arn"`
	HasConsolePwd  bool   `json:"has_console_password"`
	MFAEnabled     bool   `json:"mfa_enabled"`
	Severity       string `json:"severity"`
	Recommendation string `json:"recommendation"`
}

// DangerousPolicyJSON represents a dangerous policy in JSON
type DangerousPolicyJSON struct {
	PolicyName     string `json:"policy_name"`
	PolicyARN      string `json:"policy_arn"`
	PolicyType     string `json:"policy_type"`
	Severity       string `json:"severity"`
	Reason         string `json:"reason"`
	Recommendation string `json:"recommendation"`
}
