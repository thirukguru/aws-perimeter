package model

import (
	"github.com/thirukguru/aws-perimeter/service/apigateway"
	"github.com/thirukguru/aws-perimeter/service/ecrsecurity"
	"github.com/thirukguru/aws-perimeter/service/guardduty"
	"github.com/thirukguru/aws-perimeter/service/messaging"
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
}
