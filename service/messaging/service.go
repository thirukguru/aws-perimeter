// Package messaging provides SES/SNS abuse detection.
package messaging

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
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

// MessagingSecurityRisk represents SNS/SQS security misconfigurations
type MessagingSecurityRisk struct {
	Service        string
	RiskType       string
	Severity       string
	Resource       string
	Description    string
	Recommendation string
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
	sqsClient *sqs.Client
}

// Service is the interface for SES/SNS abuse detection
type Service interface {
	GetSESAbuseRisks(ctx context.Context) ([]SESAbuseRisk, error)
	GetSNSAbuseRisks(ctx context.Context) ([]SNSAbuseRisk, error)
	GetSendingQuotaStatus(ctx context.Context) (*SendingQuotaStatus, error)
	GetMessagingSecurityRisks(ctx context.Context) ([]MessagingSecurityRisk, error)
}

// NewService creates a new messaging abuse detection service
func NewService(cfg aws.Config) Service {
	return &service{
		sesClient: ses.NewFromConfig(cfg),
		snsClient: sns.NewFromConfig(cfg),
		sqsClient: sqs.NewFromConfig(cfg),
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

// GetMessagingSecurityRisks checks SNS/SQS security posture
func (s *service) GetMessagingSecurityRisks(ctx context.Context) ([]MessagingSecurityRisk, error) {
	var risks []MessagingSecurityRisk

	// SNS checks: public topics, unencrypted topics
	snsPaginator := sns.NewListTopicsPaginator(s.snsClient, &sns.ListTopicsInput{})
	for snsPaginator.HasMorePages() {
		page, err := snsPaginator.NextPage(ctx)
		if err != nil {
			break // SNS may be unavailable in this account/region
		}
		for _, topic := range page.Topics {
			topicARN := aws.ToString(topic.TopicArn)
			attrs, err := s.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
				TopicArn: topic.TopicArn,
			})
			if err != nil {
				continue
			}

			policy := attrs.Attributes["Policy"]
			if isPublicPolicy(policy) {
				risks = append(risks, MessagingSecurityRisk{
					Service:        "SNS",
					RiskType:       "PublicSNSTopic",
					Severity:       SeverityHigh,
					Resource:       topicARN,
					Description:    "SNS topic policy allows public principal (*)",
					Recommendation: "Restrict topic policy to specific principals and conditions",
				})
			}

			if strings.TrimSpace(attrs.Attributes["KmsMasterKeyId"]) == "" {
				risks = append(risks, MessagingSecurityRisk{
					Service:        "SNS",
					RiskType:       "UnencryptedSNS",
					Severity:       SeverityMedium,
					Resource:       topicARN,
					Description:    "SNS topic is not encrypted with KMS",
					Recommendation: "Enable SNS server-side encryption using a KMS key",
				})
			}
		}
	}

	// SQS checks: public queues, unencrypted queues, missing DLQ
	sqsPaginator := sqs.NewListQueuesPaginator(s.sqsClient, &sqs.ListQueuesInput{})
	for sqsPaginator.HasMorePages() {
		page, err := sqsPaginator.NextPage(ctx)
		if err != nil {
			break // SQS may be unavailable in this account/region
		}
		for _, queueURL := range page.QueueUrls {
			attrs, err := s.sqsClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: aws.String(queueURL),
				AttributeNames: []sqstypes.QueueAttributeName{
					sqstypes.QueueAttributeNameQueueArn,
					sqstypes.QueueAttributeNamePolicy,
					sqstypes.QueueAttributeNameKmsMasterKeyId,
					sqstypes.QueueAttributeNameSqsManagedSseEnabled,
					sqstypes.QueueAttributeNameRedrivePolicy,
				},
			})
			if err != nil {
				continue
			}

			queueARN := attrs.Attributes["QueueArn"]
			if queueARN == "" {
				queueARN = queueURL
			}

			if isPublicPolicy(attrs.Attributes["Policy"]) {
				risks = append(risks, MessagingSecurityRisk{
					Service:        "SQS",
					RiskType:       "PublicSQSQueue",
					Severity:       SeverityHigh,
					Resource:       queueARN,
					Description:    "SQS queue policy allows public principal (*)",
					Recommendation: "Restrict queue policy to specific principals and source conditions",
				})
			}

			kmsKeyID := strings.TrimSpace(attrs.Attributes["KmsMasterKeyId"])
			sseManaged := strings.EqualFold(strings.TrimSpace(attrs.Attributes["SqsManagedSseEnabled"]), "true")
			if kmsKeyID == "" && !sseManaged {
				risks = append(risks, MessagingSecurityRisk{
					Service:        "SQS",
					RiskType:       "UnencryptedSQS",
					Severity:       SeverityMedium,
					Resource:       queueARN,
					Description:    "SQS queue does not have server-side encryption enabled",
					Recommendation: "Enable SSE-SQS or SSE-KMS for the queue",
				})
			}

			if strings.TrimSpace(attrs.Attributes["RedrivePolicy"]) == "" {
				risks = append(risks, MessagingSecurityRisk{
					Service:        "SQS",
					RiskType:       "MissingSQSDeadLetterQueue",
					Severity:       SeverityMedium,
					Resource:       queueARN,
					Description:    "SQS queue has no dead-letter queue configured",
					Recommendation: "Configure a dead-letter queue to retain failed messages",
				})
			}
		}
	}

	return risks, nil
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

func isPublicPolicy(policy string) bool {
	if strings.TrimSpace(policy) == "" {
		return false
	}
	return strings.Contains(policy, "\"Principal\":\"*\"") ||
		strings.Contains(policy, "\"Principal\": \"*\"") ||
		strings.Contains(policy, "\"AWS\":\"*\"") ||
		strings.Contains(policy, "\"AWS\": \"*\"")
}
