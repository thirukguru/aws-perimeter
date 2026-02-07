// Package iam provides a service for IAM security analysis.
package iam

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// Severity constants for IAM findings
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// PrivEscRisk represents a privilege escalation risk finding
type PrivEscRisk struct {
	PrincipalType    string   // "User" or "Role"
	PrincipalName    string   // IAM user or role name
	PrincipalARN     string   // Full ARN
	EscalationPath   string   // Description of how escalation could occur
	DangerousActions []string // The specific actions that enable escalation
	Severity         string
	Recommendation   string
}

// StaleCredential represents a stale or unused credential
type StaleCredential struct {
	UserName          string
	CredentialType    string // "access_key" or "password"
	AccessKeyID       string // Only for access keys
	CreatedDate       string
	LastUsedDate      string
	DaysSinceLastUse  int
	DaysSinceCreation int
	Severity          string
	Recommendation    string
}

// CrossAccountTrust represents a cross-account trust relationship
type CrossAccountTrust struct {
	RoleName           string
	RoleARN            string
	TrustedAccountID   string
	TrustedPrincipal   string // Could be root, specific role, or "*"
	IsExternalAccount  bool   // True if not same account
	AllowsAnyPrincipal bool   // True if Principal is "*"
	Severity           string
	Description        string
	Recommendation     string
}

// UserMFAStatus represents MFA status for a user
type UserMFAStatus struct {
	UserName                string
	UserARN                 string
	HasConsolePwd           bool
	MFAEnabled              bool
	LastPasswordUse         string
	PasswordLastChanged     string
	DaysSincePasswordChange int
	Severity                string
	Recommendation          string
}

// DangerousPolicy represents an overly permissive policy
type DangerousPolicy struct {
	PolicyName     string
	PolicyARN      string
	PolicyType     string   // "AWS Managed", "Customer Managed", "Inline"
	AttachedTo     []string // Users/Roles/Groups attached to
	DangerousStmts []DangerousStatement
	Severity       string
	Recommendation string
}

// DangerousStatement represents a risky policy statement
type DangerousStatement struct {
	Effect    string
	Actions   []string
	Resources []string
	Reason    string
}

// PermissionBoundary represents a missing or misconfigured boundary
type PermissionBoundary struct {
	PrincipalType  string // "User" or "Role"
	PrincipalName  string
	PrincipalARN   string
	HasBoundary    bool
	BoundaryARN    string
	IsAdmin        bool // Has admin-level permissions
	Severity       string
	Recommendation string
}

// UnusedAdminRole represents an admin role that hasn't been used recently
type UnusedAdminRole struct {
	RoleName       string
	RoleARN        string
	LastUsedDate   string
	DaysSinceUse   int
	HasAdminAccess bool
	Severity       string
	Description    string
	Recommendation string
}

// QuarantinedUser represents a user that appears to be quarantined (compromised)
type QuarantinedUser struct {
	UserName       string
	UserARN        string
	QuarantineType string // "DENY_ALL_POLICY", "NO_PERMISSIONS", "DISABLED_KEYS"
	Indicators     []string
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	client *iam.Client
}

// Service is the interface for IAM security analysis
type Service interface {
	GetPrivilegeEscalationRisks(ctx context.Context) ([]PrivEscRisk, error)
	GetStaleCredentials(ctx context.Context, maxAgeDays int) ([]StaleCredential, error)
	GetCrossAccountTrusts(ctx context.Context, currentAccountID string) ([]CrossAccountTrust, error)
	GetUsersWithoutMFA(ctx context.Context) ([]UserMFAStatus, error)
	GetOverlyPermissivePolicies(ctx context.Context) ([]DangerousPolicy, error)
	GetMissingBoundaries(ctx context.Context) ([]PermissionBoundary, error)
	// Phase T2: Credential Exposure
	GetUnusedAdminRoles(ctx context.Context, maxAgeDays int) ([]UnusedAdminRole, error)
	GetQuarantinedUsers(ctx context.Context) ([]QuarantinedUser, error)
}

// NewService creates a new IAM service
func NewService(cfg aws.Config) Service {
	return &service{
		client: iam.NewFromConfig(cfg),
	}
}
