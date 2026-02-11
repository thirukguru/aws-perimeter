package model

import (
	"github.com/thirukguru/aws-perimeter/service/apigateway"
	"github.com/thirukguru/aws-perimeter/service/cachesecurity"
	"github.com/thirukguru/aws-perimeter/service/dataprotection"
	"github.com/thirukguru/aws-perimeter/service/ecrsecurity"
	"github.com/thirukguru/aws-perimeter/service/eventsecurity"
	"github.com/thirukguru/aws-perimeter/service/governance"
	"github.com/thirukguru/aws-perimeter/service/guardduty"
	"github.com/thirukguru/aws-perimeter/service/lambdasecurity"
	"github.com/thirukguru/aws-perimeter/service/messaging"
	"github.com/thirukguru/aws-perimeter/service/redshiftsecurity"
	"github.com/thirukguru/aws-perimeter/service/resourcepolicy"
	"github.com/thirukguru/aws-perimeter/service/securityhub"
)

// RenderAdvancedInput contains advanced security findings
type RenderAdvancedInput struct {
	AccountID string
	Region    string

	// Security Hub
	HubStatus    *securityhub.HubStatus
	HubStandards []securityhub.StandardStatus
	HubFindings  []securityhub.CriticalFinding

	// GuardDuty
	GuardDutyStatus   *guardduty.DetectorStatus
	GuardDutyFindings []guardduty.ThreatFinding

	// API Gateway
	APINoRateLimits []apigateway.RateLimitStatus
	APINoAuth       []apigateway.AuthorizationStatus
	APIRisks        []apigateway.APIRisk

	// Resource-based Policies
	LambdaPolicyRisks []resourcepolicy.ResourcePolicyRisk
	SQSPolicyRisks    []resourcepolicy.ResourcePolicyRisk
	SNSPolicyRisks    []resourcepolicy.ResourcePolicyRisk

	// Messaging Security (SNS/SQS)
	MessagingSecurityRisks []messaging.MessagingSecurityRisk

	// ECR Security
	ECRSecurityRisks []ecrsecurity.ECRRisk

	// Backup & Disaster Recovery
	BackupRisks []dataprotection.BackupRisk

	// Organizations & SCP Expansion
	OrgGuardrailRisks []governance.OrgGuardrailRisk

	// Lambda Security Expansion
	LambdaConfigRisks []lambdasecurity.LambdaConfigRisk

	// EventBridge/Step Functions
	EventWorkflowRisks []eventsecurity.EventWorkflowRisk

	// ElastiCache / MemoryDB Security
	CacheSecurityRisks []cachesecurity.CacheSecurityRisk

	// Redshift Security
	RedshiftSecurityRisks []redshiftsecurity.RedshiftRisk
}

// AdvancedReportJSON represents the JSON output for advanced security checks
type AdvancedReportJSON struct {
	AccountID   string `json:"account_id"`
	Region      string `json:"region,omitempty"`
	GeneratedAt string `json:"generated_at"`

	// Security Hub
	SecurityHubEnabled  bool                          `json:"security_hub_enabled"`
	SecurityHubFindings []securityhub.CriticalFinding `json:"security_hub_findings,omitempty"`

	// GuardDuty
	GuardDutyEnabled  bool                      `json:"guardduty_enabled"`
	GuardDutyFindings []guardduty.ThreatFinding `json:"guardduty_findings,omitempty"`

	// API Gateway
	APIsWithoutRateLimits []apigateway.RateLimitStatus     `json:"apis_without_rate_limits,omitempty"`
	APIsWithoutAuth       []apigateway.AuthorizationStatus `json:"apis_without_auth,omitempty"`

	// Resource-based Policies
	ResourcePolicyRisks []resourcepolicy.ResourcePolicyRisk `json:"resource_policy_risks,omitempty"`

	// Messaging Security (SNS/SQS)
	MessagingSecurityRisks []messaging.MessagingSecurityRisk `json:"messaging_security_risks,omitempty"`

	// ECR Security
	ECRSecurityRisks []ecrsecurity.ECRRisk `json:"ecr_security_risks,omitempty"`

	// Backup & Disaster Recovery
	BackupRisks []dataprotection.BackupRisk `json:"backup_risks,omitempty"`

	// Organizations & SCP Expansion
	OrgGuardrailRisks []governance.OrgGuardrailRisk `json:"org_guardrail_risks,omitempty"`

	// Lambda Security Expansion
	LambdaConfigRisks []lambdasecurity.LambdaConfigRisk `json:"lambda_config_risks,omitempty"`

	// EventBridge/Step Functions
	EventWorkflowRisks []eventsecurity.EventWorkflowRisk `json:"event_workflow_risks,omitempty"`

	// ElastiCache / MemoryDB Security
	CacheSecurityRisks []cachesecurity.CacheSecurityRisk `json:"cache_security_risks,omitempty"`

	// Redshift Security
	RedshiftSecurityRisks []redshiftsecurity.RedshiftRisk `json:"redshift_security_risks,omitempty"`
}
