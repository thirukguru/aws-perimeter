package model

import (
	"github.com/thirukguru/aws-perimeter/service/vpc"
)

// SecurityReportJSON represents the JSON output for security analysis.
type SecurityReportJSON struct {
	AccountID            string                  `json:"account_id"`
	GeneratedAt          string                  `json:"generated_at"`
	HasFindings          bool                    `json:"has_findings"`
	Summary              SecuritySummaryJSON     `json:"summary"`
	SecurityGroupRisks   []SecurityGroupRiskJSON `json:"security_group_risks"`
	UnusedSecurityGroups []UnusedSGJSON          `json:"unused_security_groups"`
	PublicExposureRisks  []ExposureRiskJSON      `json:"public_exposure_risks"`
	NACLRisks            []NACLRiskJSON          `json:"nacl_risks"`
	VPCFlowLogStatus     []FlowLogStatusJSON     `json:"vpc_flow_log_status"`
	IAMRisks             []IAMRiskJSON           `json:"iam_risks,omitempty"`
	PrivilegeEscalation  []EscalationRiskJSON    `json:"privilege_escalation_risks,omitempty"`
	BackdoorIndicators   []BackdoorRiskJSON      `json:"backdoor_indicators,omitempty"`
	DDoSProtectionStatus *DDoSStatusJSON         `json:"ddos_protection,omitempty"`
}

// SecuritySummaryJSON provides a summary count of findings by severity.
type SecuritySummaryJSON struct {
	TotalFindings int `json:"total_findings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
}

// SecurityGroupRiskJSON represents a risky security group configuration.
type SecurityGroupRiskJSON struct {
	SecurityGroupID   string   `json:"security_group_id"`
	SecurityGroupName string   `json:"security_group_name"`
	VpcID             string   `json:"vpc_id"`
	RiskType          string   `json:"risk_type"`
	Severity          string   `json:"severity"`
	Port              int32    `json:"port"`
	Protocol          string   `json:"protocol"`
	SourceCIDR        string   `json:"source_cidr"`
	Description       string   `json:"description"`
	Recommendation    string   `json:"recommendation"`
	AffectedResources []string `json:"affected_resources,omitempty"`
}

// UnusedSGJSON represents an unused security group.
type UnusedSGJSON struct {
	SecurityGroupID   string `json:"security_group_id"`
	SecurityGroupName string `json:"security_group_name"`
	VpcID             string `json:"vpc_id"`
	Description       string `json:"description,omitempty"`
}

// ExposureRiskJSON represents public exposure risk.
type ExposureRiskJSON struct {
	InstanceID       string   `json:"instance_id"`
	InstanceName     string   `json:"instance_name,omitempty"`
	PublicIP         string   `json:"public_ip"`
	SecurityGroupIDs []string `json:"security_group_ids"`
	OpenPorts        []int32  `json:"open_ports"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Recommendation   string   `json:"recommendation"`
}

// NACLRiskJSON represents a risky NACL configuration.
type NACLRiskJSON struct {
	NetworkAclID string   `json:"network_acl_id"`
	VpcID        string   `json:"vpc_id"`
	SubnetIDs    []string `json:"subnet_ids"`
	RuleNumber   int32    `json:"rule_number"`
	IsEgress     bool     `json:"is_egress"`
	Protocol     string   `json:"protocol"`
	PortRange    string   `json:"port_range"`
	CidrBlock    string   `json:"cidr_block"`
	RuleAction   string   `json:"rule_action"`
	Severity     string   `json:"severity"`
	Description  string   `json:"description"`
}

// FlowLogStatusJSON represents VPC flow log status.
type FlowLogStatusJSON struct {
	VpcID           string   `json:"vpc_id"`
	VpcName         string   `json:"vpc_name,omitempty"`
	FlowLogsEnabled bool     `json:"flow_logs_enabled"`
	FlowLogIDs      []string `json:"flow_log_ids,omitempty"`
	Severity        string   `json:"severity"`
	Recommendation  string   `json:"recommendation,omitempty"`
}

// IAMRiskJSON represents an IAM security risk.
type IAMRiskJSON struct {
	PrincipalArn   string `json:"principal_arn"`
	PrincipalType  string `json:"principal_type"` // "user" or "role"
	PrincipalName  string `json:"principal_name"`
	RiskType       string `json:"risk_type"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// EscalationRiskJSON represents a privilege escalation risk.
type EscalationRiskJSON struct {
	PrincipalArn     string   `json:"principal_arn"`
	PrincipalName    string   `json:"principal_name"`
	EscalationPath   string   `json:"escalation_path"`
	RiskyPermissions []string `json:"risky_permissions"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Recommendation   string   `json:"recommendation"`
}

// BackdoorRiskJSON represents a potential backdoor indicator.
type BackdoorRiskJSON struct {
	ResourceArn    string `json:"resource_arn"`
	ResourceType   string `json:"resource_type"`
	IndicatorType  string `json:"indicator_type"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// DDoSStatusJSON represents DDoS protection status.
type DDoSStatusJSON struct {
	ShieldAdvancedEnabled bool                      `json:"shield_advanced_enabled"`
	ProtectedResources    int                       `json:"protected_resources"`
	UnprotectedResources  []UnprotectedResourceJSON `json:"unprotected_resources,omitempty"`
	WAFCoverage           []WAFCoverageJSON         `json:"waf_coverage,omitempty"`
}

// UnprotectedResourceJSON represents a resource without DDoS protection.
type UnprotectedResourceJSON struct {
	ResourceArn  string `json:"resource_arn"`
	ResourceType string `json:"resource_type"`
	Severity     string `json:"severity"`
}

// WAFCoverageJSON represents WAF coverage for a resource.
type WAFCoverageJSON struct {
	ResourceArn  string `json:"resource_arn"`
	ResourceType string `json:"resource_type"`
	HasWAF       bool   `json:"has_waf"`
	WebACLArn    string `json:"web_acl_arn,omitempty"`
}

// RenderSecurityInput represents the input data for rendering the security report.
type RenderSecurityInput struct {
	AccountID            string
	SecurityGroupRisks   []vpc.SGRisk
	UnusedSecurityGroups []vpc.UnusedSG
	PublicExposureRisks  []vpc.ExposureRisk
	NACLRisks            []vpc.NACLRisk
	VPCFlowLogStatus     []vpc.FlowLogStatus
	// Phase T: Nation-State Threat Detection
	ManagementExposure []vpc.ManagementExposure
	PlaintextRisks     []vpc.PlaintextRisk
	IMDSv1Risks        []vpc.IMDSv1Risk
}
