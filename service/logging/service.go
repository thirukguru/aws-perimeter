// Package logging provides CloudWatch, Access Analyzer, and logging security analysis.
package logging

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// CloudWatchStatus represents CloudWatch Logs configuration
type CloudWatchStatus struct {
	LogGroupCount       int
	RetentionConfigured int
	EncryptedGroups     int
	Severity            string
	Description         string
	Recommendation      string
}

// LogGroupRisk represents a log group with security issues
type LogGroupRisk struct {
	LogGroupName   string
	RetentionDays  int32
	IsEncrypted    bool
	StoredBytes    int64
	Severity       string
	Description    string
	Recommendation string
}

// AccessAnalyzerStatus represents IAM Access Analyzer status
type AccessAnalyzerStatus struct {
	AnalyzersEnabled int
	ActiveFindings   int
	CriticalFindings int
	Severity         string
	Description      string
	Recommendation   string
}

// ExternalAccessFinding represents an IAM Access Analyzer finding
type ExternalAccessFinding struct {
	FindingID      string
	ResourceARN    string
	ResourceType   string
	Principal      string
	IsPublic       bool
	Status         string
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	logsClient     *cloudwatchlogs.Client
	analyzerClient *accessanalyzer.Client
}

// Service is the interface for logging security analysis
type Service interface {
	GetCloudWatchStatus(ctx context.Context) (*CloudWatchStatus, error)
	GetLogGroupRisks(ctx context.Context) ([]LogGroupRisk, error)
	GetAccessAnalyzerStatus(ctx context.Context) (*AccessAnalyzerStatus, error)
	GetExternalAccessFindings(ctx context.Context) ([]ExternalAccessFinding, error)
}

// NewService creates a new logging service
func NewService(cfg aws.Config) Service {
	return &service{
		logsClient:     cloudwatchlogs.NewFromConfig(cfg),
		analyzerClient: accessanalyzer.NewFromConfig(cfg),
	}
}

// GetCloudWatchStatus checks overall CloudWatch Logs configuration
func (s *service) GetCloudWatchStatus(ctx context.Context) (*CloudWatchStatus, error) {
	status := &CloudWatchStatus{}

	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(s.logsClient, &cloudwatchlogs.DescribeLogGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, lg := range page.LogGroups {
			status.LogGroupCount++
			if lg.RetentionInDays != nil {
				status.RetentionConfigured++
			}
			if lg.KmsKeyId != nil {
				status.EncryptedGroups++
			}
		}
	}

	if status.LogGroupCount == 0 {
		status.Severity = SeverityHigh
		status.Description = "No CloudWatch Log Groups found"
		status.Recommendation = "Configure CloudWatch Logs for application and security logging"
	} else if status.RetentionConfigured < status.LogGroupCount/2 {
		status.Severity = SeverityMedium
		status.Description = fmt.Sprintf("Only %d/%d log groups have retention configured", status.RetentionConfigured, status.LogGroupCount)
		status.Recommendation = "Configure retention policies to manage costs and compliance"
	} else {
		status.Severity = SeverityLow
		status.Description = "CloudWatch Logs properly configured"
		status.Recommendation = "Continue monitoring log configurations"
	}

	return status, nil
}

// GetLogGroupRisks finds log groups with security issues
func (s *service) GetLogGroupRisks(ctx context.Context) ([]LogGroupRisk, error) {
	var risks []LogGroupRisk

	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(s.logsClient, &cloudwatchlogs.DescribeLogGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, lg := range page.LogGroups {
			var issues []string
			severity := SeverityLow

			retentionDays := int32(0)
			if lg.RetentionInDays != nil {
				retentionDays = *lg.RetentionInDays
			}
			isEncrypted := lg.KmsKeyId != nil
			storedBytes := int64(0)
			if lg.StoredBytes != nil {
				storedBytes = *lg.StoredBytes
			}

			// No retention = logs kept forever (cost & compliance risk)
			if retentionDays == 0 && storedBytes > 1024*1024*1024 { // >1GB
				issues = append(issues, "no retention policy with large volume")
				severity = SeverityMedium
			}

			// Unencrypted with large data
			if !isEncrypted && storedBytes > 1024*1024*100 { // >100MB
				issues = append(issues, "unencrypted logs")
				if severity == SeverityLow {
					severity = SeverityMedium
				}
			}

			if len(issues) > 0 {
				risks = append(risks, LogGroupRisk{
					LogGroupName:   aws.ToString(lg.LogGroupName),
					RetentionDays:  retentionDays,
					IsEncrypted:    isEncrypted,
					StoredBytes:    storedBytes,
					Severity:       severity,
					Description:    joinStrings(issues),
					Recommendation: "Configure retention and KMS encryption",
				})
			}
		}
	}

	return risks, nil
}

// GetAccessAnalyzerStatus checks IAM Access Analyzer configuration
func (s *service) GetAccessAnalyzerStatus(ctx context.Context) (*AccessAnalyzerStatus, error) {
	status := &AccessAnalyzerStatus{}

	analyzers, err := s.analyzerClient.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{})
	if err != nil {
		status.Severity = SeverityHigh
		status.Description = "IAM Access Analyzer not configured"
		status.Recommendation = "Enable IAM Access Analyzer to detect external access"
		return status, nil
	}

	status.AnalyzersEnabled = len(analyzers.Analyzers)

	// Count findings across all analyzers
	for _, analyzer := range analyzers.Analyzers {
		findings, err := s.analyzerClient.ListFindings(ctx, &accessanalyzer.ListFindingsInput{
			AnalyzerArn: analyzer.Arn,
		})
		if err != nil {
			continue
		}

		for _, f := range findings.Findings {
			status.ActiveFindings++
			if f.Status == "ACTIVE" {
				status.CriticalFindings++
			}
		}
	}

	if status.AnalyzersEnabled == 0 {
		status.Severity = SeverityHigh
		status.Description = "No IAM Access Analyzers enabled"
		status.Recommendation = "Enable Access Analyzer for the account/organization"
	} else if status.CriticalFindings > 0 {
		status.Severity = SeverityHigh
		status.Description = fmt.Sprintf("%d active external access findings", status.CriticalFindings)
		status.Recommendation = "Review and remediate Access Analyzer findings"
	} else {
		status.Severity = SeverityLow
		status.Description = "Access Analyzer enabled with no active findings"
		status.Recommendation = "Continue monitoring for new findings"
	}

	return status, nil
}

// GetExternalAccessFindings returns active Access Analyzer findings
func (s *service) GetExternalAccessFindings(ctx context.Context) ([]ExternalAccessFinding, error) {
	var findings []ExternalAccessFinding

	analyzers, err := s.analyzerClient.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{})
	if err != nil {
		return findings, nil
	}

	for _, analyzer := range analyzers.Analyzers {
		findingsResp, err := s.analyzerClient.ListFindings(ctx, &accessanalyzer.ListFindingsInput{
			AnalyzerArn: analyzer.Arn,
		})
		if err != nil {
			continue
		}

		for _, f := range findingsResp.Findings {
			if f.Status != "ACTIVE" {
				continue
			}

			severity := SeverityMedium
			if f.IsPublic != nil && *f.IsPublic {
				severity = SeverityCritical
			}

			findings = append(findings, ExternalAccessFinding{
				FindingID:      aws.ToString(f.Id),
				ResourceARN:    aws.ToString(f.Resource),
				ResourceType:   string(f.ResourceType),
				IsPublic:       f.IsPublic != nil && *f.IsPublic,
				Status:         string(f.Status),
				Severity:       severity,
				Description:    "External access detected to resource",
				Recommendation: "Review and restrict access or archive finding if intended",
			})
		}
	}

	return findings, nil
}

func joinStrings(s []string) string {
	if len(s) == 0 {
		return ""
	}
	result := s[0]
	for i := 1; i < len(s); i++ {
		result += ", " + s[i]
	}
	return result
}

// Suppress unused import warning
var _ types.LogGroup
