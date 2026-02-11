// Package cloudtrail provides CloudTrail audit analysis.
package cloudtrail

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityInfo     = "INFO"
)

// TrailStatus represents the status of a CloudTrail trail
type TrailStatus struct {
	TrailName        string
	TrailARN         string
	IsMultiRegion    bool
	IsLogging        bool
	IsOrganization   bool
	HasLogValidation bool
	S3BucketName     string
	Severity         string
	Recommendation   string
}

// TrailGap represents a gap in CloudTrail coverage
type TrailGap struct {
	Issue          string
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	client *cloudtrail.Client
}

// Service is the interface for CloudTrail audit
type Service interface {
	GetTrailStatus(ctx context.Context) ([]TrailStatus, error)
	GetTrailGaps(ctx context.Context) ([]TrailGap, error)
}

// NewService creates a new CloudTrail service
func NewService(cfg aws.Config) Service {
	return &service{
		client: cloudtrail.NewFromConfig(cfg),
	}
}

// GetTrailStatus retrieves status of all trails
func (s *service) GetTrailStatus(ctx context.Context) ([]TrailStatus, error) {
	var statuses []TrailStatus

	trails, err := s.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}

	for _, trail := range trails.TrailList {
		status := TrailStatus{
			TrailName:        aws.ToString(trail.Name),
			TrailARN:         aws.ToString(trail.TrailARN),
			IsMultiRegion:    aws.ToBool(trail.IsMultiRegionTrail),
			IsOrganization:   aws.ToBool(trail.IsOrganizationTrail),
			HasLogValidation: aws.ToBool(trail.LogFileValidationEnabled),
			S3BucketName:     aws.ToString(trail.S3BucketName),
		}

		// Check if trail is logging
		trailStatus, err := s.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.Name,
		})
		if err == nil {
			status.IsLogging = aws.ToBool(trailStatus.IsLogging)
		}

		// Determine severity
		if !status.IsLogging {
			status.Severity = SeverityCritical
			status.Recommendation = "Enable logging for this trail"
		} else if !status.IsMultiRegion {
			status.Severity = SeverityMedium
			status.Recommendation = "Consider enabling multi-region logging"
		} else if !status.HasLogValidation {
			status.Severity = SeverityMedium
			status.Recommendation = "Enable log file validation for integrity"
		} else {
			status.Severity = SeverityInfo
			status.Recommendation = "Trail is properly configured"
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// GetTrailGaps identifies gaps in CloudTrail coverage
func (s *service) GetTrailGaps(ctx context.Context) ([]TrailGap, error) {
	var gaps []TrailGap

	trails, err := s.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}

	// Check if any trails exist
	if len(trails.TrailList) == 0 {
		gaps = append(gaps, TrailGap{
			Issue:          "NO_TRAILS",
			Severity:       SeverityCritical,
			Description:    "No CloudTrail trails are configured",
			Recommendation: "Create a multi-region trail with management events enabled",
		})
		return gaps, nil
	}

	// Check for multi-region trail
	hasMultiRegion := false
	hasLogging := false
	hasValidation := false

	for _, trail := range trails.TrailList {
		if aws.ToBool(trail.IsMultiRegionTrail) {
			hasMultiRegion = true
		}

		if aws.ToBool(trail.LogFileValidationEnabled) {
			hasValidation = true
		}

		// Check if logging
		status, err := s.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.Name,
		})
		if err == nil && aws.ToBool(status.IsLogging) {
			hasLogging = true
		}
	}

	if !hasMultiRegion {
		gaps = append(gaps, TrailGap{
			Issue:          "NO_MULTI_REGION",
			Severity:       SeverityHigh,
			Description:    "No multi-region trail configured",
			Recommendation: "Create a multi-region trail to capture activity in all regions",
		})
	}

	if !hasLogging {
		gaps = append(gaps, TrailGap{
			Issue:          "NO_ACTIVE_LOGGING",
			Severity:       SeverityCritical,
			Description:    "No trails are actively logging",
			Recommendation: "Enable logging on at least one trail",
		})
	}

	if !hasValidation {
		gaps = append(gaps, TrailGap{
			Issue:          "NO_LOG_VALIDATION",
			Severity:       SeverityMedium,
			Description:    "No trails have log file validation enabled",
			Recommendation: "Enable log file validation to detect log tampering",
		})
	}

	return gaps, nil
}
