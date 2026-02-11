// Package lambdasecurity provides Lambda security analysis.
package lambdasecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// OverlyPermissiveRole represents a Lambda with overly permissive IAM role
type OverlyPermissiveRole struct {
	FunctionName     string
	FunctionARN      string
	RoleARN          string
	RoleName         string
	DangerousActions []string
	HasAdminAccess   bool
	Severity         string
	Description      string
	Recommendation   string
}

// CrossRegionExecution represents potential cross-region Lambda execution anomaly
type CrossRegionExecution struct {
	FunctionName   string
	FunctionARN    string
	CurrentRegion  string
	TargetRegions  []string
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	lambdaClient *lambda.Client
	iamClient    *iam.Client
	region       string
}

// Service is the interface for Lambda security analysis
type Service interface {
	GetOverlyPermissiveRoles(ctx context.Context) ([]OverlyPermissiveRole, error)
	GetCrossRegionExecution(ctx context.Context) ([]CrossRegionExecution, error)
}

// NewService creates a new Lambda security service
func NewService(cfg aws.Config) Service {
	return &service{
		lambdaClient: lambda.NewFromConfig(cfg),
		iamClient:    iam.NewFromConfig(cfg),
		region:       cfg.Region,
	}
}

// Dangerous Lambda permissions that enable credential exposure attacks
var dangerousLambdaActions = map[string]string{
	"*":                         "Full admin access",
	"iam:*":                     "Full IAM access",
	"iam:CreateUser":            "Can create IAM users",
	"iam:CreateAccessKey":       "Can create access keys",
	"iam:AttachUserPolicy":      "Can attach policies to users",
	"iam:AttachRolePolicy":      "Can attach policies to roles",
	"iam:PassRole":              "Can pass roles to services",
	"sts:AssumeRole":            "Can assume other roles",
	"s3:*":                      "Full S3 access",
	"secretsmanager:GetSecret*": "Can read secrets",
	"ssm:GetParameter*":         "Can read SSM parameters",
	"kms:Decrypt":               "Can decrypt data",
	"ses:SendEmail":             "Can send emails (phishing risk)",
	"sns:Publish":               "Can publish to SNS (abuse risk)",
}

// GetOverlyPermissiveRoles finds Lambda functions with dangerous IAM permissions
func (s *service) GetOverlyPermissiveRoles(ctx context.Context) ([]OverlyPermissiveRole, error) {
	var risks []OverlyPermissiveRole

	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Lambda functions: %w", err)
		}

		for _, fn := range page.Functions {
			if fn.Role == nil {
				continue
			}

			roleARN := aws.ToString(fn.Role)
			roleName := extractRoleName(roleARN)

			dangerousActions := s.analyzeLambdaRole(ctx, roleName)

			if len(dangerousActions) > 0 {
				hasAdmin := containsAdminAccess(dangerousActions)
				severity := SeverityHigh
				if hasAdmin {
					severity = SeverityCritical
				}

				risks = append(risks, OverlyPermissiveRole{
					FunctionName:     aws.ToString(fn.FunctionName),
					FunctionARN:      aws.ToString(fn.FunctionArn),
					RoleARN:          roleARN,
					RoleName:         roleName,
					DangerousActions: dangerousActions,
					HasAdminAccess:   hasAdmin,
					Severity:         severity,
					Description:      fmt.Sprintf("Lambda has %d dangerous permissions", len(dangerousActions)),
					Recommendation:   "Apply least-privilege principle - remove unnecessary permissions",
				})
			}
		}
	}

	return risks, nil
}

// GetCrossRegionExecution detects Lambda functions with cross-region access
func (s *service) GetCrossRegionExecution(ctx context.Context) ([]CrossRegionExecution, error) {
	var risks []CrossRegionExecution

	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Lambda functions: %w", err)
		}

		for _, fn := range page.Functions {
			if fn.Role == nil {
				continue
			}

			roleARN := aws.ToString(fn.Role)
			roleName := extractRoleName(roleARN)

			// Check if role has cross-region resource access
			targetRegions := s.getCrossRegionResources(ctx, roleName)

			if len(targetRegions) > 0 {
				risks = append(risks, CrossRegionExecution{
					FunctionName:   aws.ToString(fn.FunctionName),
					FunctionARN:    aws.ToString(fn.FunctionArn),
					CurrentRegion:  s.region,
					TargetRegions:  targetRegions,
					Severity:       SeverityMedium,
					Description:    "Lambda has cross-region resource access - potential data exfiltration vector",
					Recommendation: "Review if cross-region access is necessary, restrict to specific regions",
				})
			}
		}
	}

	return risks, nil
}

func (s *service) analyzeLambdaRole(ctx context.Context, roleName string) []string {
	var dangerous []string

	// Get attached policies
	attached, err := s.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil
	}

	for _, policy := range attached.AttachedPolicies {
		policyARN := aws.ToString(policy.PolicyArn)

		// Check for AdministratorAccess
		if strings.Contains(policyARN, "AdministratorAccess") {
			dangerous = append(dangerous, "AdministratorAccess (Full Admin)")
			continue
		}

		// Analyze policy document
		actions := s.getPolicyDangerousActions(ctx, policyARN)
		dangerous = append(dangerous, actions...)
	}

	// Check inline policies
	inline, err := s.iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		for _, policyName := range inline.PolicyNames {
			policyDoc, err := s.iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err == nil && policyDoc.PolicyDocument != nil {
				actions := extractDangerousActionsFromDoc(*policyDoc.PolicyDocument)
				dangerous = append(dangerous, actions...)
			}
		}
	}

	return uniqueStrings(dangerous)
}

func (s *service) getPolicyDangerousActions(ctx context.Context, policyARN string) []string {
	policy, err := s.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(policyARN),
	})
	if err != nil {
		return nil
	}

	version, err := s.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN),
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil || version.PolicyVersion.Document == nil {
		return nil
	}

	return extractDangerousActionsFromDoc(*version.PolicyVersion.Document)
}

func (s *service) getCrossRegionResources(ctx context.Context, roleName string) []string {
	var regions []string
	regionSet := make(map[string]bool)

	// This is a simplified check - in production you'd analyze policy resources
	// for ARNs containing different regions
	attached, err := s.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil
	}

	for _, policy := range attached.AttachedPolicies {
		policyARN := aws.ToString(policy.PolicyArn)

		// Check for broad resource access that could be cross-region
		if strings.Contains(policyARN, "AmazonS3FullAccess") ||
			strings.Contains(policyARN, "AmazonDynamoDBFullAccess") {
			regionSet["*"] = true
		}
	}

	for region := range regionSet {
		if region != s.region {
			regions = append(regions, region)
		}
	}

	return regions
}

type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}

func extractDangerousActionsFromDoc(encodedDoc string) []string {
	var dangerous []string

	decoded, err := url.QueryUnescape(encodedDoc)
	if err != nil {
		return nil
	}

	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		actions := normalizeStringOrSlice(stmt.Action)

		for _, action := range actions {
			// Check for wildcard admin
			if action == "*" {
				dangerous = append(dangerous, "*:* (Full Admin)")
				continue
			}

			// Check against known dangerous actions
			for dangerousAction := range dangerousLambdaActions {
				if actionMatches(action, dangerousAction) {
					dangerous = append(dangerous, action)
				}
			}
		}
	}

	return dangerous
}

func normalizeStringOrSlice(v interface{}) []string {
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

func actionMatches(pattern, action string) bool {
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)

	if pattern == action {
		return true
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(action, prefix)
	}

	return false
}

func extractRoleName(roleARN string) string {
	parts := strings.Split(roleARN, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return roleARN
}

func containsAdminAccess(actions []string) bool {
	for _, action := range actions {
		if strings.Contains(action, "Full Admin") || strings.Contains(action, "AdministratorAccess") {
			return true
		}
	}
	return false
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
