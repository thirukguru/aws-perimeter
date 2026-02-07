// Package messaging provides SES/SNS abuse detection.
package messaging

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// SESAbuseRisk represents potential SES abuse indicators
type SESAbuseRisk struct {
	IdentityARN      string
	IdentityType     string // "Email", "Domain"
	IdentityName     string
	BounceRate       float64
	ComplaintRate    float64
	ReputationStatus string
	Severity         string
	Description      string
	Recommendation   string
}

// SNSAbuseRisk represents potential SNS abuse indicators
type SNSAbuseRisk struct {
	TopicARN        string
	TopicName       string
	SubscriberCount int
	IsPublic        bool
	Severity        string
	Description     string
	Recommendation  string
}

// SendingQuotaStatus represents SES sending quota status
type SendingQuotaStatus struct {
	Max24HourSend   float64
	SentLast24Hours float64
	MaxSendRate     float64
	UsagePercent    float64
	Severity        string
	Description     string
}

type service struct {
	sesClient *ses.Client
	snsClient *sns.Client
}

// Service is the interface for SES/SNS abuse detection
type Service interface {
	GetSESAbuseRisks(ctx context.Context) ([]SESAbuseRisk, error)
	GetSNSAbuseRisks(ctx context.Context) ([]SNSAbuseRisk, error)
	GetSendingQuotaStatus(ctx context.Context) (*SendingQuotaStatus, error)
}

// NewService creates a new messaging abuse detection service
func NewService(cfg aws.Config) Service {
	return &service{
		sesClient: ses.NewFromConfig(cfg),
		snsClient: sns.NewFromConfig(cfg),
	}
}

// GetSESAbuseRisks checks for SES abuse indicators
// Based on threat intel - compromised accounts used for phishing campaigns
func (s *service) GetSESAbuseRisks(ctx context.Context) ([]SESAbuseRisk, error) {
	var risks []SESAbuseRisk

	// Get account sending statistics
	stats, err := s.sesClient.GetSendStatistics(ctx, &ses.GetSendStatisticsInput{})
	if err != nil {
		return risks, nil // SES not configured
	}

	// Analyze recent sending patterns
	var totalSent, totalBounces, totalComplaints int64
	cutoff := time.Now().Add(-24 * time.Hour)

	for _, point := range stats.SendDataPoints {
		if point.Timestamp != nil && point.Timestamp.After(cutoff) {
			totalSent += point.DeliveryAttempts
			totalBounces += point.Bounces
			totalComplaints += point.Complaints
		}
	}

	if totalSent > 0 {
		bounceRate := float64(totalBounces) / float64(totalSent) * 100
		complaintRate := float64(totalComplaints) / float64(totalSent) * 100

		// AWS suspends accounts with >5% bounce or >0.1% complaint rate
		if bounceRate > 5.0 || complaintRate > 0.1 {
			severity := SeverityMedium
			if bounceRate > 10.0 || complaintRate > 0.5 {
				severity = SeverityHigh
			}

			risks = append(risks, SESAbuseRisk{
				IdentityType:     "Account",
				IdentityName:     "SES Account",
				BounceRate:       bounceRate,
				ComplaintRate:    complaintRate,
				ReputationStatus: "AT_RISK",
				Severity:         severity,
				Description:      "High bounce/complaint rates may indicate phishing or compromised credentials",
				Recommendation:   "Review sending patterns, verify recipient lists, check for unauthorized access",
			})
		}
	}

	// Check verified identities
	identities, err := s.sesClient.ListIdentities(ctx, &ses.ListIdentitiesInput{})
	if err == nil {
		// Check for suspicious patterns in verified identities
		if len(identities.Identities) > 50 {
			risks = append(risks, SESAbuseRisk{
				IdentityType:   "Account",
				IdentityName:   "Multiple Identities",
				Severity:       SeverityMedium,
				Description:    "Large number of verified identities - may indicate abuse",
				Recommendation: "Review and remove unused verified identities",
			})
		}
	}

	return risks, nil
}

// GetSNSAbuseRisks checks for SNS abuse indicators
func (s *service) GetSNSAbuseRisks(ctx context.Context) ([]SNSAbuseRisk, error) {
	var risks []SNSAbuseRisk

	// List all topics
	topics, err := s.snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
	if err != nil {
		return risks, nil // SNS not configured
	}

	for _, topic := range topics.Topics {
		topicARN := aws.ToString(topic.TopicArn)

		// Get topic attributes
		attrs, err := s.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
			TopicArn: topic.TopicArn,
		})
		if err != nil {
			continue
		}

		// Check for public access
		policy := attrs.Attributes["Policy"]
		isPublic := policy != "" && (contains(policy, "\"AWS\":\"*\"") ||
			contains(policy, "\"Principal\":\"*\""))

		if isPublic {
			risks = append(risks, SNSAbuseRisk{
				TopicARN:       topicARN,
				TopicName:      extractTopicName(topicARN),
				IsPublic:       true,
				Severity:       SeverityHigh,
				Description:    "SNS topic has public access - potential abuse vector",
				Recommendation: "Restrict SNS topic access to specific principals",
			})
		}

		// Check subscription count
		subs, _ := s.snsClient.ListSubscriptionsByTopic(ctx, &sns.ListSubscriptionsByTopicInput{
			TopicArn: topic.TopicArn,
		})
		if subs != nil && len(subs.Subscriptions) > 100 {
			risks = append(risks, SNSAbuseRisk{
				TopicARN:        topicARN,
				TopicName:       extractTopicName(topicARN),
				SubscriberCount: len(subs.Subscriptions),
				Severity:        SeverityMedium,
				Description:     "Large number of subscribers - verify if legitimate",
				Recommendation:  "Review subscriber list for unauthorized additions",
			})
		}
	}

	return risks, nil
}

// GetSendingQuotaStatus checks SES sending quota usage
func (s *service) GetSendingQuotaStatus(ctx context.Context) (*SendingQuotaStatus, error) {
	quota, err := s.sesClient.GetSendQuota(ctx, &ses.GetSendQuotaInput{})
	if err != nil {
		return nil, nil // SES not configured
	}

	usagePercent := 0.0
	if quota.Max24HourSend > 0 {
		usagePercent = (quota.SentLast24Hours / quota.Max24HourSend) * 100
	}

	status := &SendingQuotaStatus{
		Max24HourSend:   quota.Max24HourSend,
		SentLast24Hours: quota.SentLast24Hours,
		MaxSendRate:     quota.MaxSendRate,
		UsagePercent:    usagePercent,
		Severity:        SeverityLow,
		Description:     "Normal sending patterns",
	}

	if usagePercent > 80 {
		status.Severity = SeverityMedium
		status.Description = "High quota usage - may indicate abuse or need for limit increase"
	}

	if usagePercent > 95 {
		status.Severity = SeverityHigh
		status.Description = "Critical quota usage - investigate for potential abuse"
	}

	return status, nil
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				containsSubstr(s, substr)))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func extractTopicName(arn string) string {
	// ARN format: arn:aws:sns:region:account:topic-name
	for i := len(arn) - 1; i >= 0; i-- {
		if arn[i] == ':' {
			return arn[i+1:]
		}
	}
	return arn
}
