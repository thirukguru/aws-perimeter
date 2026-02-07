// Package guardduty provides GuardDuty status and findings analysis.
package guardduty

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// DetectorStatus represents GuardDuty detector status
type DetectorStatus struct {
	IsEnabled         bool
	DetectorID        string
	ServiceRole       string
	FindingPublishing string
	Severity          string
	Recommendation    string
}

// ThreatFinding represents a GuardDuty finding
type ThreatFinding struct {
	Title         string
	Type          string
	Severity      float64
	SeverityLabel string
	ResourceType  string
	ResourceID    string
	Description   string
	Count         int
	FirstSeen     string
	LastSeen      string
}

type service struct {
	client *guardduty.Client
}

// Service is the interface for GuardDuty analysis
type Service interface {
	GetDetectorStatus(ctx context.Context) (*DetectorStatus, error)
	GetThreatFindings(ctx context.Context, limit int) ([]ThreatFinding, error)
}

// NewService creates a new GuardDuty service
func NewService(cfg aws.Config) Service {
	return &service{
		client: guardduty.NewFromConfig(cfg),
	}
}

// GetDetectorStatus checks if GuardDuty is enabled
func (s *service) GetDetectorStatus(ctx context.Context) (*DetectorStatus, error) {
	// List detectors
	detectors, err := s.client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return &DetectorStatus{
			IsEnabled:      false,
			Severity:       SeverityCritical,
			Recommendation: "Enable AWS GuardDuty for threat detection",
		}, nil
	}

	if len(detectors.DetectorIds) == 0 {
		return &DetectorStatus{
			IsEnabled:      false,
			Severity:       SeverityCritical,
			Recommendation: "Enable AWS GuardDuty for threat detection",
		}, nil
	}

	detectorID := detectors.DetectorIds[0]

	// Get detector details
	detector, err := s.client.GetDetector(ctx, &guardduty.GetDetectorInput{
		DetectorId: aws.String(detectorID),
	})
	if err != nil {
		return nil, err
	}

	status := &DetectorStatus{
		DetectorID:  detectorID,
		ServiceRole: aws.ToString(detector.ServiceRole),
		IsEnabled:   detector.Status == types.DetectorStatusEnabled,
	}

	if status.IsEnabled {
		status.Severity = SeverityInfo
		status.Recommendation = "GuardDuty is enabled and monitoring"
	} else {
		status.Severity = SeverityCritical
		status.Recommendation = "GuardDuty detector is disabled - enable immediately"
	}

	return status, nil
}

// GetThreatFindings gets recent threat findings
func (s *service) GetThreatFindings(ctx context.Context, limit int) ([]ThreatFinding, error) {
	var findings []ThreatFinding

	detectors, err := s.client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil || len(detectors.DetectorIds) == 0 {
		return findings, nil
	}

	detectorID := detectors.DetectorIds[0]

	// Get findings sorted by severity
	findingsInput := &guardduty.ListFindingsInput{
		DetectorId: aws.String(detectorID),
		SortCriteria: &types.SortCriteria{
			AttributeName: aws.String("severity"),
			OrderBy:       types.OrderByDesc,
		},
		MaxResults: aws.Int32(int32(limit)),
	}

	findingIDs, err := s.client.ListFindings(ctx, findingsInput)
	if err != nil {
		return nil, err
	}

	if len(findingIDs.FindingIds) == 0 {
		return findings, nil
	}

	// Get finding details
	details, err := s.client.GetFindings(ctx, &guardduty.GetFindingsInput{
		DetectorId: aws.String(detectorID),
		FindingIds: findingIDs.FindingIds,
	})
	if err != nil {
		return nil, err
	}

	for _, f := range details.Findings {
		severity := aws.ToFloat64(f.Severity)
		severityLabel := SeverityLow
		if severity >= 7.0 {
			severityLabel = SeverityCritical
		} else if severity >= 4.0 {
			severityLabel = SeverityMedium
		}

		resourceType := ""
		resourceID := ""
		if f.Resource != nil {
			resourceType = aws.ToString(f.Resource.ResourceType)
			if f.Resource.InstanceDetails != nil {
				resourceID = aws.ToString(f.Resource.InstanceDetails.InstanceId)
			} else if f.Resource.AccessKeyDetails != nil {
				resourceID = aws.ToString(f.Resource.AccessKeyDetails.AccessKeyId)
			}
		}

		findings = append(findings, ThreatFinding{
			Title:         aws.ToString(f.Title),
			Type:          aws.ToString(f.Type),
			Severity:      severity,
			SeverityLabel: severityLabel,
			ResourceType:  resourceType,
			ResourceID:    resourceID,
			Description:   truncate(aws.ToString(f.Description), 80),
			Count:         int(aws.ToInt32(f.Service.Count)),
			FirstSeen:     aws.ToString(f.Service.EventFirstSeen),
			LastSeen:      aws.ToString(f.Service.EventLastSeen),
		})
	}

	return findings, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
