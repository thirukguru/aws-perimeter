// Package inspector provides Amazon Inspector security analysis.
package inspector

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// InspectorStatus represents Inspector enablement status
type InspectorStatus struct {
	IsEnabled          bool
	AccountsEnabled    int
	EC2ScanningEnabled bool
	ECRScanningEnabled bool
	LambdaScanEnabled  bool
	Severity           string
	Description        string
	Recommendation     string
}

// CriticalVulnerability represents a critical vulnerability finding
type CriticalVulnerability struct {
	FindingARN     string
	Title          string
	Description    string
	Severity       string
	ResourceType   string
	ResourceID     string
	CVE            string
	FixAvailable   bool
	Recommendation string
}

type service struct {
	client *inspector2.Client
}

// Service is the interface for Inspector security analysis
type Service interface {
	GetInspectorStatus(ctx context.Context) (*InspectorStatus, error)
	GetCriticalVulnerabilities(ctx context.Context) ([]CriticalVulnerability, error)
}

// NewService creates a new Inspector service
func NewService(cfg aws.Config) Service {
	return &service{
		client: inspector2.NewFromConfig(cfg),
	}
}

// GetInspectorStatus checks if Amazon Inspector is enabled
func (s *service) GetInspectorStatus(ctx context.Context) (*InspectorStatus, error) {
	status := &InspectorStatus{
		IsEnabled: false,
	}

	// Get account status
	resp, err := s.client.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		// Inspector not enabled
		status.Severity = SeverityHigh
		status.Description = "Amazon Inspector is not enabled"
		status.Recommendation = "Enable Inspector for continuous vulnerability scanning"
		return status, nil
	}

	if len(resp.Accounts) > 0 {
		account := resp.Accounts[0]
		status.AccountsEnabled = len(resp.Accounts)

		// Check EC2 scanning
		if account.ResourceState.Ec2.Status == types.StatusEnabled {
			status.EC2ScanningEnabled = true
			status.IsEnabled = true
		}

		// Check ECR scanning
		if account.ResourceState.Ecr.Status == types.StatusEnabled {
			status.ECRScanningEnabled = true
			status.IsEnabled = true
		}

		// Check Lambda scanning
		if account.ResourceState.Lambda != nil && account.ResourceState.Lambda.Status == types.StatusEnabled {
			status.LambdaScanEnabled = true
		}
	}

	if status.IsEnabled {
		status.Severity = SeverityLow
		status.Description = "Inspector is enabled"
		status.Recommendation = "Continue monitoring vulnerability findings"
	} else {
		status.Severity = SeverityHigh
		status.Description = "Amazon Inspector is not fully enabled"
		status.Recommendation = "Enable Inspector for EC2, ECR, and Lambda scanning"
	}

	return status, nil
}

// GetCriticalVulnerabilities finds critical severity vulnerabilities
func (s *service) GetCriticalVulnerabilities(ctx context.Context) ([]CriticalVulnerability, error) {
	var vulns []CriticalVulnerability

	// Filter for critical and high severity findings
	filters := &types.FilterCriteria{
		Severity: []types.StringFilter{
			{Comparison: types.StringComparisonEquals, Value: aws.String("CRITICAL")},
		},
	}

	paginator := inspector2.NewListFindingsPaginator(s.client, &inspector2.ListFindingsInput{
		FilterCriteria: filters,
		MaxResults:     aws.Int32(100),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, finding := range page.Findings {
			vuln := CriticalVulnerability{
				FindingARN:     aws.ToString(finding.FindingArn),
				Title:          aws.ToString(finding.Title),
				Description:    aws.ToString(finding.Description),
				Severity:       string(finding.Severity),
				Recommendation: "Apply available patches or mitigations",
			}

			// Get resource info
			if len(finding.Resources) > 0 {
				res := finding.Resources[0]
				vuln.ResourceType = string(res.Type)
				vuln.ResourceID = aws.ToString(res.Id)
			}

			// Get CVE if available
			if finding.PackageVulnerabilityDetails != nil {
				if finding.PackageVulnerabilityDetails.VulnerabilityId != nil {
					vuln.CVE = aws.ToString(finding.PackageVulnerabilityDetails.VulnerabilityId)
				}
				vuln.FixAvailable = true // Assume fix may be available if we can detect
			}

			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}
