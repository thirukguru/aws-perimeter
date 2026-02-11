// Package eventsecurity provides EventBridge and Step Functions security analysis.
package eventsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// EventWorkflowRisk represents EventBridge / Step Functions misconfiguration risk.
type EventWorkflowRisk struct {
	Service        string
	RiskType       string
	Severity       string
	Resource       string
	Description    string
	Recommendation string
}

type service struct {
	eventClient *eventbridge.Client
	sfnClient   *sfn.Client
	iamClient   *iam.Client
}

// Service is the interface for EventBridge / Step Functions security checks.
type Service interface {
	GetEventWorkflowRisks(ctx context.Context) ([]EventWorkflowRisk, error)
}

// NewService creates a new event security service.
func NewService(cfg aws.Config) Service {
	return &service{
		eventClient: eventbridge.NewFromConfig(cfg),
		sfnClient:   sfn.NewFromConfig(cfg),
		iamClient:   iam.NewFromConfig(cfg),
	}
}

// GetEventWorkflowRisks evaluates EventBridge and Step Functions risks.
func (s *service) GetEventWorkflowRisks(ctx context.Context) ([]EventWorkflowRisk, error) {
	risks := []EventWorkflowRisk{}

	eventBusRisks, err := s.getOpenEventBusRisks(ctx)
	if err != nil {
		return nil, err
	}
	risks = append(risks, eventBusRisks...)

	stepFunctionRisks, err := s.getStepFunctionRisks(ctx)
	if err != nil {
		return nil, err
	}
	risks = append(risks, stepFunctionRisks...)

	return risks, nil
}

func (s *service) getOpenEventBusRisks(ctx context.Context) ([]EventWorkflowRisk, error) {
	var risks []EventWorkflowRisk

	var nextToken *string
	for {
		page, err := s.eventClient.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{
			NextToken: nextToken,
		})
		if err != nil {
			// EventBridge unavailable or not authorized in this account/region.
			return risks, nil
		}

		for _, bus := range page.EventBuses {
			busName := aws.ToString(bus.Name)
			if busName == "" || busName == "default" {
				// Scope this check to custom buses as roadmap item specifies.
				continue
			}

			describeOut, err := s.eventClient.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{
				Name: aws.String(busName),
			})
			if err != nil {
				continue
			}

			policy := aws.ToString(describeOut.Policy)
			if hasPublicPrincipal(policy) {
				risks = append(risks, EventWorkflowRisk{
					Service:        "EventBridge",
					RiskType:       "OpenEventBridgeBus",
					Severity:       SeverityHigh,
					Resource:       busName,
					Description:    "Custom event bus policy allows public principals",
					Recommendation: "Restrict event bus policy principals to explicit AWS account IDs, roles, or organizations conditions",
				})
			}
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			break
		}
		nextToken = page.NextToken
	}

	return risks, nil
}

func (s *service) getStepFunctionRisks(ctx context.Context) ([]EventWorkflowRisk, error) {
	var risks []EventWorkflowRisk

	paginator := sfn.NewListStateMachinesPaginator(s.sfnClient, &sfn.ListStateMachinesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// Step Functions unavailable or not authorized in this account/region.
			return risks, nil
		}

		for _, sm := range page.StateMachines {
			smName := aws.ToString(sm.Name)
			smARN := aws.ToString(sm.StateMachineArn)
			if smARN == "" {
				continue
			}

			detail, err := s.sfnClient.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
				StateMachineArn: aws.String(smARN),
			})
			if err != nil {
				continue
			}

			if isStepFunctionLoggingDisabled(detail.LoggingConfiguration) {
				risks = append(risks, EventWorkflowRisk{
					Service:        "StepFunctions",
					RiskType:       "StepFunctionLoggingDisabled",
					Severity:       SeverityMedium,
					Resource:       smName,
					Description:    "State machine does not have CloudWatch logging enabled",
					Recommendation: "Enable Step Functions logging at ERROR or ALL level with a dedicated CloudWatch log group",
				})
			}

			if detail.Type == sfntypes.StateMachineTypeExpress {
				isPublic, err := s.expressStateMachineRolePublic(ctx, aws.ToString(detail.RoleArn))
				if err != nil {
					continue
				}
				if isPublic {
					risks = append(risks, EventWorkflowRisk{
						Service:        "StepFunctions",
						RiskType:       "StateMachinePublicExposure",
						Severity:       SeverityHigh,
						Resource:       smName,
						Description:    "Express state machine execution role trust policy is overly permissive",
						Recommendation: "Restrict trust policy principals and require strict conditions for assume-role paths",
					})
				}
			}
		}
	}

	return risks, nil
}

func (s *service) expressStateMachineRolePublic(ctx context.Context, roleARN string) (bool, error) {
	roleName := extractRoleName(roleARN)
	if roleName == "" {
		return false, nil
	}
	roleOut, err := s.iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	if err != nil {
		return false, fmt.Errorf("failed to get role %s: %w", roleName, err)
	}
	if roleOut.Role == nil || roleOut.Role.AssumeRolePolicyDocument == nil {
		return false, nil
	}
	doc, err := url.QueryUnescape(aws.ToString(roleOut.Role.AssumeRolePolicyDocument))
	if err != nil {
		return false, nil
	}
	return hasPublicPrincipal(doc), nil
}

func isStepFunctionLoggingDisabled(cfg *sfntypes.LoggingConfiguration) bool {
	if cfg == nil {
		return true
	}
	if cfg.Level == sfntypes.LogLevelOff {
		return true
	}
	return len(cfg.Destinations) == 0
}

func extractRoleName(roleARN string) string {
	parts := strings.Split(roleARN, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func hasPublicPrincipal(policyDoc string) bool {
	if strings.TrimSpace(policyDoc) == "" {
		return false
	}

	var policy map[string]interface{}
	if err := json.Unmarshal([]byte(policyDoc), &policy); err != nil {
		return false
	}

	statements := normalizeStatements(policy["Statement"])
	for _, stmt := range statements {
		if !isAllowStatement(stmt) {
			continue
		}
		if principalIsPublic(stmt["Principal"]) {
			return true
		}
	}
	return false
}

func normalizeStatements(v interface{}) []map[string]interface{} {
	switch s := v.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{s}
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(s))
		for _, item := range s {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func isAllowStatement(stmt map[string]interface{}) bool {
	effect, ok := stmt["Effect"].(string)
	if !ok {
		return false
	}
	return strings.EqualFold(effect, "Allow")
}

func principalIsPublic(principal interface{}) bool {
	switch p := principal.(type) {
	case string:
		return p == "*"
	case map[string]interface{}:
		for _, v := range p {
			if principalValueIsPublic(v) {
				return true
			}
		}
	}
	return false
}

func principalValueIsPublic(v interface{}) bool {
	switch x := v.(type) {
	case string:
		return x == "*"
	case []interface{}:
		for _, item := range x {
			if s, ok := item.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}
