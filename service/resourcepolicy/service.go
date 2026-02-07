// Package resourcepolicy provides resource-based IAM policy analysis.
package resourcepolicy

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// PolicyStatement represents a parsed IAM policy statement
type PolicyStatement struct {
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal"`
	Action    interface{} `json:"Action"`
	Resource  interface{} `json:"Resource"`
	Condition interface{} `json:"Condition,omitempty"`
}

// ResourcePolicyRisk represents a risk in a resource-based policy
type ResourcePolicyRisk struct {
	ResourceType   string
	ResourceName   string
	ResourceARN    string
	RiskType       string
	Severity       string
	Principal      string
	Actions        []string
	HasCondition   bool
	ConditionKeys  []string
	Description    string
	Recommendation string
}

// BoundaryStatus represents permission boundary analysis
type BoundaryStatus struct {
	PrincipalType  string
	PrincipalName  string
	PrincipalARN   string
	HasBoundary    bool
	BoundaryARN    string
	Severity       string
	Recommendation string
}

type service struct {
	lambdaClient *lambda.Client
	sqsClient    *sqs.Client
	snsClient    *sns.Client
}

// Service is the interface for resource policy analysis
type Service interface {
	GetLambdaPolicyRisks(ctx context.Context) ([]ResourcePolicyRisk, error)
	GetSQSPolicyRisks(ctx context.Context) ([]ResourcePolicyRisk, error)
	GetSNSPolicyRisks(ctx context.Context) ([]ResourcePolicyRisk, error)
}

// NewService creates a new resource policy service
func NewService(cfg aws.Config) Service {
	return &service{
		lambdaClient: lambda.NewFromConfig(cfg),
		sqsClient:    sqs.NewFromConfig(cfg),
		snsClient:    sns.NewFromConfig(cfg),
	}
}

// GetLambdaPolicyRisks analyzes Lambda function policies
func (s *service) GetLambdaPolicyRisks(ctx context.Context) ([]ResourcePolicyRisk, error) {
	var risks []ResourcePolicyRisk

	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, fn := range page.Functions {
			policy, err := s.lambdaClient.GetPolicy(ctx, &lambda.GetPolicyInput{
				FunctionName: fn.FunctionName,
			})
			if err != nil {
				continue // No policy is fine
			}

			if policy.Policy == nil {
				continue
			}

			policyRisks := analyzePolicyDocument(*policy.Policy, "Lambda", aws.ToString(fn.FunctionName), aws.ToString(fn.FunctionArn))
			risks = append(risks, policyRisks...)
		}
	}

	return risks, nil
}

// GetSQSPolicyRisks analyzes SQS queue policies
func (s *service) GetSQSPolicyRisks(ctx context.Context) ([]ResourcePolicyRisk, error) {
	var risks []ResourcePolicyRisk

	queues, err := s.sqsClient.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return nil, err
	}

	for _, url := range queues.QueueUrls {
		attrs, err := s.sqsClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl:       aws.String(url),
			AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNamePolicy, sqstypes.QueueAttributeNameQueueArn},
		})
		if err != nil {
			continue
		}

		policy, ok := attrs.Attributes["Policy"]
		if !ok || policy == "" {
			continue
		}

		queueARN := attrs.Attributes["QueueArn"]
		queueName := extractQueueName(url)

		policyRisks := analyzePolicyDocument(policy, "SQS", queueName, queueARN)
		risks = append(risks, policyRisks...)
	}

	return risks, nil
}

// GetSNSPolicyRisks analyzes SNS topic policies
func (s *service) GetSNSPolicyRisks(ctx context.Context) ([]ResourcePolicyRisk, error) {
	var risks []ResourcePolicyRisk

	topics, err := s.snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
	if err != nil {
		return nil, err
	}

	for _, topic := range topics.Topics {
		attrs, err := s.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
			TopicArn: topic.TopicArn,
		})
		if err != nil {
			continue
		}

		policy, ok := attrs.Attributes["Policy"]
		if !ok || policy == "" {
			continue
		}

		topicName := extractTopicName(aws.ToString(topic.TopicArn))

		policyRisks := analyzePolicyDocument(policy, "SNS", topicName, aws.ToString(topic.TopicArn))
		risks = append(risks, policyRisks...)
	}

	return risks, nil
}

func analyzePolicyDocument(policyJSON, resourceType, resourceName, resourceARN string) []ResourcePolicyRisk {
	var risks []ResourcePolicyRisk

	var doc struct {
		Statement []PolicyStatement `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return risks
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		principal := principalToString(stmt.Principal)
		actions := normalizeToSlice(stmt.Action)
		hasCondition := stmt.Condition != nil
		conditionKeys := extractConditionKeys(stmt.Condition)

		// Check for overly permissive principal
		if principal == "*" {
			severity := SeverityCritical
			recommendation := "Restrict principal to specific AWS accounts/services"

			// If there's a condition, it might be intentional
			if hasCondition && len(conditionKeys) > 0 {
				severity = SeverityHigh
				recommendation = "Review conditions - principal is * but has conditions: " + strings.Join(conditionKeys, ", ")
			}

			risks = append(risks, ResourcePolicyRisk{
				ResourceType:   resourceType,
				ResourceName:   resourceName,
				ResourceARN:    resourceARN,
				RiskType:       "PUBLIC_PRINCIPAL",
				Severity:       severity,
				Principal:      principal,
				Actions:        actions,
				HasCondition:   hasCondition,
				ConditionKeys:  conditionKeys,
				Description:    "Policy allows any principal (*)",
				Recommendation: recommendation,
			})
		}

		// Check for dangerous actions
		for _, action := range actions {
			if action == "*" || strings.HasSuffix(action, ":*") {
				risks = append(risks, ResourcePolicyRisk{
					ResourceType:   resourceType,
					ResourceName:   resourceName,
					ResourceARN:    resourceARN,
					RiskType:       "WILDCARD_ACTION",
					Severity:       SeverityHigh,
					Principal:      principal,
					Actions:        actions,
					HasCondition:   hasCondition,
					ConditionKeys:  conditionKeys,
					Description:    "Policy allows wildcard actions",
					Recommendation: "Use specific actions instead of wildcards",
				})
				break
			}
		}

		// Check for cross-account access without conditions
		if isExternalPrincipal(principal) && !hasCondition {
			risks = append(risks, ResourcePolicyRisk{
				ResourceType:   resourceType,
				ResourceName:   resourceName,
				ResourceARN:    resourceARN,
				RiskType:       "CROSS_ACCOUNT_NO_CONDITION",
				Severity:       SeverityMedium,
				Principal:      principal,
				Actions:        actions,
				HasCondition:   hasCondition,
				Description:    "Cross-account access without conditions",
				Recommendation: "Add conditions like aws:SourceAccount, aws:SourceArn",
			})
		}
	}

	return risks
}

func principalToString(p interface{}) string {
	switch v := p.(type) {
	case string:
		return v
	case map[string]interface{}:
		if aws, ok := v["AWS"]; ok {
			return principalToString(aws)
		}
		if svc, ok := v["Service"]; ok {
			return principalToString(svc)
		}
	case []interface{}:
		if len(v) > 0 {
			return principalToString(v[0])
		}
	}
	return ""
}

func normalizeToSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func extractConditionKeys(condition interface{}) []string {
	var keys []string
	if condition == nil {
		return keys
	}

	condMap, ok := condition.(map[string]interface{})
	if !ok {
		return keys
	}

	for operator, conditions := range condMap {
		if condInner, ok := conditions.(map[string]interface{}); ok {
			for key := range condInner {
				keys = append(keys, operator+":"+key)
			}
		}
	}

	return keys
}

func isExternalPrincipal(principal string) bool {
	// Check if principal contains an AWS account ID that might be external
	if strings.Contains(principal, ":root") {
		return true
	}
	// Simple heuristic - if it's an ARN with account ID
	return strings.HasPrefix(principal, "arn:aws") && strings.Contains(principal, "::")
}

func extractQueueName(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func extractTopicName(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}
