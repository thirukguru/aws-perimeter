// Package cloudtrailsecurity provides CloudTrail-based security analysis.
package cloudtrailsecurity

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// IAMRoleCreationEvent represents a recent IAM role creation
type IAMRoleCreationEvent struct {
	EventTime      time.Time
	EventID        string
	RoleName       string
	CreatedBy      string
	SourceIP       string
	UserAgent      string
	IsAutomated    bool
	Severity       string
	Description    string
	Recommendation string
}

// SuspiciousActivity represents suspicious API activity
type SuspiciousActivity struct {
	EventTime   time.Time
	EventName   string
	EventSource string
	UserName    string
	SourceIP    string
	ErrorCode   string
	Severity    string
	Description string
}

// RootAccountUsage represents root account activity
type RootAccountUsage struct {
	EventTime      time.Time
	EventName      string
	SourceIP       string
	UserAgent      string
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	client *cloudtrail.Client
}

// Service is the interface for CloudTrail security analysis
type Service interface {
	GetRecentRoleCreations(ctx context.Context, hours int) ([]IAMRoleCreationEvent, error)
	GetSuspiciousActivity(ctx context.Context, hours int) ([]SuspiciousActivity, error)
	GetRootAccountUsage(ctx context.Context, hours int) ([]RootAccountUsage, error)
}

// NewService creates a new CloudTrail security service
func NewService(cfg aws.Config) Service {
	return &service{
		client: cloudtrail.NewFromConfig(cfg),
	}
}

// GetRecentRoleCreations monitors for recent IAM role creation activity
// Based on threat intel - attackers create backdoor roles for persistence
func (s *service) GetRecentRoleCreations(ctx context.Context, hours int) ([]IAMRoleCreationEvent, error) {
	var creations []IAMRoleCreationEvent

	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	paginator := cloudtrail.NewLookupEventsPaginator(s.client, &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(startTime),
		EndTime:   aws.Time(endTime),
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyEventName,
				AttributeValue: aws.String("CreateRole"),
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, event := range page.Events {
			roleName := extractRoleNameFromEvent(aws.ToString(event.CloudTrailEvent))
			sourceIP := extractFieldFromEvent(aws.ToString(event.CloudTrailEvent), "sourceIPAddress")
			userAgent := extractFieldFromEvent(aws.ToString(event.CloudTrailEvent), "userAgent")

			// Determine if automated (console, SDK, etc.)
			isAutomated := strings.Contains(userAgent, "aws-sdk") ||
				strings.Contains(userAgent, "terraform") ||
				strings.Contains(userAgent, "cloudformation")

			severity := SeverityLow
			description := "Routine role creation"

			// Suspicious indicators
			if !isAutomated {
				severity = SeverityMedium
				description = "Manual role creation via console"
			}

			// Check for suspicious patterns
			roleNameLower := strings.ToLower(roleName)
			if strings.Contains(roleNameLower, "admin") ||
				strings.Contains(roleNameLower, "backdoor") ||
				strings.Contains(roleNameLower, "temp") {
				severity = SeverityHigh
				description = "Role name contains suspicious keywords"
			}

			creations = append(creations, IAMRoleCreationEvent{
				EventTime:      aws.ToTime(event.EventTime),
				EventID:        aws.ToString(event.EventId),
				RoleName:       roleName,
				CreatedBy:      aws.ToString(event.Username),
				SourceIP:       sourceIP,
				UserAgent:      userAgent,
				IsAutomated:    isAutomated,
				Severity:       severity,
				Description:    description,
				Recommendation: "Verify role creation was authorized and follows naming conventions",
			})
		}
	}

	return creations, nil
}

// GetSuspiciousActivity finds suspicious API patterns
func (s *service) GetSuspiciousActivity(ctx context.Context, hours int) ([]SuspiciousActivity, error) {
	var suspicious []SuspiciousActivity

	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	// Look for failed privilege escalation attempts
	suspiciousEvents := []string{
		"AssumeRole",
		"GetSecretValue",
		"GetParameter",
		"CreateAccessKey",
		"AttachUserPolicy",
		"AttachRolePolicy",
	}

	for _, eventName := range suspiciousEvents {
		paginator := cloudtrail.NewLookupEventsPaginator(s.client, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(startTime),
			EndTime:   aws.Time(endTime),
			LookupAttributes: []types.LookupAttribute{
				{
					AttributeKey:   types.LookupAttributeKeyEventName,
					AttributeValue: aws.String(eventName),
				},
			},
			MaxResults: aws.Int32(50),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				break
			}

			for _, event := range page.Events {
				eventData := aws.ToString(event.CloudTrailEvent)
				errorCode := extractFieldFromEvent(eventData, "errorCode")

				// Only interested in failed attempts (access denied, etc.)
				if errorCode == "" {
					continue
				}

				if strings.Contains(errorCode, "AccessDenied") ||
					strings.Contains(errorCode, "UnauthorizedAccess") {
					suspicious = append(suspicious, SuspiciousActivity{
						EventTime:   aws.ToTime(event.EventTime),
						EventName:   aws.ToString(event.EventName),
						EventSource: aws.ToString(event.EventSource),
						UserName:    aws.ToString(event.Username),
						SourceIP:    extractFieldFromEvent(eventData, "sourceIPAddress"),
						ErrorCode:   errorCode,
						Severity:    SeverityMedium,
						Description: "Failed privilege escalation attempt",
					})
				}
			}
		}
	}

	return suspicious, nil
}

// GetRootAccountUsage detects root account API activity
// Root usage is a critical security finding - should use IAM users/roles instead
func (s *service) GetRootAccountUsage(ctx context.Context, hours int) ([]RootAccountUsage, error) {
	var rootUsage []RootAccountUsage

	endTime := time.Now()
	startTime := endTime.Add(-time.Duration(hours) * time.Hour)

	// Look for root user activity
	paginator := cloudtrail.NewLookupEventsPaginator(s.client, &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(startTime),
		EndTime:   aws.Time(endTime),
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyUsername,
				AttributeValue: aws.String("root"),
			},
		},
		MaxResults: aws.Int32(100),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, event := range page.Events {
			eventData := aws.ToString(event.CloudTrailEvent)
			sourceIP := extractFieldFromEvent(eventData, "sourceIPAddress")
			userAgent := extractFieldFromEvent(eventData, "userAgent")

			severity := SeverityHigh
			description := "Root account API activity detected"

			// Console logins are critical
			eventName := aws.ToString(event.EventName)
			if eventName == "ConsoleLogin" {
				severity = SeverityCritical
				description = "Root account console login detected"
			}

			rootUsage = append(rootUsage, RootAccountUsage{
				EventTime:      aws.ToTime(event.EventTime),
				EventName:      eventName,
				SourceIP:       sourceIP,
				UserAgent:      userAgent,
				Severity:       severity,
				Description:    description,
				Recommendation: "Use IAM users/roles instead of root account, enable MFA on root",
			})
		}
	}

	return rootUsage, nil
}

func extractRoleNameFromEvent(eventData string) string {
	return extractFieldFromEvent(eventData, "roleName")
}

func extractFieldFromEvent(eventData, field string) string {
	// Simple JSON field extraction (production should use proper JSON parsing)
	search := "\"" + field + "\":\""
	idx := strings.Index(eventData, search)
	if idx == -1 {
		return ""
	}
	start := idx + len(search)
	end := strings.Index(eventData[start:], "\"")
	if end == -1 {
		return ""
	}
	return eventData[start : start+end]
}
