// Package securityhub provides Security Hub status and findings analysis.
package securityhub

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// HubStatus represents Security Hub enablement status
type HubStatus struct {
	IsEnabled      bool
	HubARN         string
	AutoEnable     bool
	Severity       string
	Recommendation string
}

// StandardStatus represents a security standard status
type StandardStatus struct {
	StandardName   string
	StandardARN    string
	IsEnabled      bool
	ControlsPassed int
	ControlsFailed int
	ControlsTotal  int
	Severity       string
	Recommendation string
}

// CriticalFinding represents a critical/high severity finding
type CriticalFinding struct {
	Title        string
	Description  string
	ResourceType string
	ResourceID   string
	Severity     string
	Compliance   string
	ProductName  string
}

type service struct {
	client *securityhub.Client
}

// Service is the interface for Security Hub analysis
type Service interface {
	GetHubStatus(ctx context.Context) (*HubStatus, error)
	GetStandardsStatus(ctx context.Context) ([]StandardStatus, error)
	GetCriticalFindings(ctx context.Context, limit int) ([]CriticalFinding, error)
}

// NewService creates a new Security Hub service
func NewService(cfg aws.Config) Service {
	return &service{
		client: securityhub.NewFromConfig(cfg),
	}
}

// GetHubStatus checks if Security Hub is enabled
func (s *service) GetHubStatus(ctx context.Context) (*HubStatus, error) {
	hub, err := s.client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		// Security Hub not enabled
		return &HubStatus{
			IsEnabled:      false,
			Severity:       SeverityCritical,
			Recommendation: "Enable AWS Security Hub for centralized security findings",
		}, nil
	}

	return &HubStatus{
		IsEnabled:      true,
		HubARN:         aws.ToString(hub.HubArn),
		AutoEnable:     aws.ToBool(hub.AutoEnableControls),
		Severity:       SeverityInfo,
		Recommendation: "Security Hub is enabled",
	}, nil
}

// GetStandardsStatus checks enabled security standards
func (s *service) GetStandardsStatus(ctx context.Context) ([]StandardStatus, error) {
	var statuses []StandardStatus

	hubStatus, err := s.GetHubStatus(ctx)
	if err != nil || !hubStatus.IsEnabled {
		return statuses, nil
	}

	standards, err := s.client.GetEnabledStandards(ctx, &securityhub.GetEnabledStandardsInput{})
	if err != nil {
		return nil, err
	}

	for _, std := range standards.StandardsSubscriptions {
		status := StandardStatus{
			StandardARN: aws.ToString(std.StandardsArn),
			IsEnabled:   std.StandardsStatus == types.StandardsStatusReady,
		}

		// Extract standard name from ARN
		status.StandardName = extractStandardName(aws.ToString(std.StandardsArn))

		if status.IsEnabled {
			status.Severity = SeverityInfo
			status.Recommendation = "Standard is enabled and active"
		} else {
			status.Severity = SeverityMedium
			status.Recommendation = "Enable this security standard"
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// GetCriticalFindings gets recent critical/high findings
func (s *service) GetCriticalFindings(ctx context.Context, limit int) ([]CriticalFinding, error) {
	var findings []CriticalFinding

	hubStatus, err := s.GetHubStatus(ctx)
	if err != nil || !hubStatus.IsEnabled {
		return findings, nil
	}

	// Get critical and high severity findings
	input := &securityhub.GetFindingsInput{
		Filters: &types.AwsSecurityFindingFilters{
			SeverityLabel: []types.StringFilter{
				{Value: aws.String("CRITICAL"), Comparison: types.StringFilterComparisonEquals},
			},
			RecordState: []types.StringFilter{
				{Value: aws.String("ACTIVE"), Comparison: types.StringFilterComparisonEquals},
			},
		},
		MaxResults: aws.Int32(int32(limit)),
	}

	result, err := s.client.GetFindings(ctx, input)
	if err != nil {
		return nil, err
	}

	for _, f := range result.Findings {
		resourceType := ""
		resourceID := ""
		if len(f.Resources) > 0 {
			resourceType = aws.ToString(f.Resources[0].Type)
			resourceID = aws.ToString(f.Resources[0].Id)
		}

		compliance := "UNKNOWN"
		if f.Compliance != nil {
			compliance = string(f.Compliance.Status)
		}

		findings = append(findings, CriticalFinding{
			Title:        aws.ToString(f.Title),
			Description:  truncate(aws.ToString(f.Description), 100),
			ResourceType: resourceType,
			ResourceID:   extractResourceName(resourceID),
			Severity:     string(f.Severity.Label),
			Compliance:   compliance,
			ProductName:  aws.ToString(f.ProductName),
		})
	}

	return findings, nil
}

func extractStandardName(arn string) string {
	// Simple extraction from ARN
	names := map[string]string{
		"aws-foundational-security-best-practices": "AWS Foundational Security",
		"cis-aws-foundations-benchmark":            "CIS AWS Foundations",
		"pci-dss":                                  "PCI DSS",
		"nist-800-53":                              "NIST 800-53",
	}
	for key, name := range names {
		if contains(arn, key) {
			return name
		}
	}
	return arn
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func extractResourceName(id string) string {
	if len(id) > 50 {
		return id[len(id)-50:]
	}
	return id
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
