// Package lambdasecurity provides Lambda security analysis.
package lambdasecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
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

// LambdaConfigRisk represents Lambda runtime/configuration security risks.
type LambdaConfigRisk struct {
	RiskType         string
	FunctionName     string
	FunctionARN      string
	Severity         string
	Description      string
	Recommendation   string
	SupportingDetail string
}

type service struct {
	lambdaClient *lambda.Client
	iamClient    *iam.Client
	ec2Client    *ec2.Client
	region       string
}

// Service is the interface for Lambda security analysis
type Service interface {
	GetOverlyPermissiveRoles(ctx context.Context) ([]OverlyPermissiveRole, error)
	GetCrossRegionExecution(ctx context.Context) ([]CrossRegionExecution, error)
	GetLambdaConfigRisks(ctx context.Context) ([]LambdaConfigRisk, error)
}

// NewService creates a new Lambda security service
func NewService(cfg aws.Config) Service {
	return &service{
		lambdaClient: lambda.NewFromConfig(cfg),
		iamClient:    iam.NewFromConfig(cfg),
		ec2Client:    ec2.NewFromConfig(cfg),
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

var defaultLayerAllowlist = []string{
	"arn:aws:lambda:us-east-1:580247275435:layer:LambdaInsightsExtension",
	"arn:aws:lambda:us-east-1:017000801446:layer:AWSLambdaPowertoolsPython",
	"arn:aws:lambda:us-east-1:017000801446:layer:AWSLambdaPowertoolsTypeScript",
	"arn:aws:lambda:us-east-1:017000801446:layer:AWSLambdaPowertoolsJava",
	"arn:aws:lambda:us-east-1:017000801446:layer:AWSLambdaPowertoolsDotnet",
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

// GetLambdaConfigRisks evaluates Lambda configuration posture risks.
func (s *service) GetLambdaConfigRisks(ctx context.Context) ([]LambdaConfigRisk, error) {
	var risks []LambdaConfigRisk

	natSubnets, subnetsWithEndpoints, err := s.getVPCConnectivityState(ctx)
	if err != nil {
		return nil, err
	}

	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Lambda functions: %w", err)
		}
		for _, fn := range page.Functions {
			functionName := aws.ToString(fn.FunctionName)
			functionARN := aws.ToString(fn.FunctionArn)

			if hasRiskyVPCConfig(fn, natSubnets, subnetsWithEndpoints) {
				risks = append(risks, LambdaConfigRisk{
					RiskType:       "VPCNoNATOrVPCEndpoints",
					FunctionName:   functionName,
					FunctionARN:    functionARN,
					Severity:       SeverityHigh,
					Description:    "Function runs in a VPC without NAT or VPC endpoint egress coverage",
					Recommendation: "Add NAT Gateway/Instance or required Interface/Gateway VPC Endpoints for AWS service access",
				})
			}

			disabled, err := s.hasReservedConcurrencyZero(ctx, functionName)
			if err != nil {
				return nil, err
			}
			if disabled {
				risks = append(risks, LambdaConfigRisk{
					RiskType:       "ReservedConcurrencyZero",
					FunctionName:   functionName,
					FunctionARN:    functionARN,
					Severity:       SeverityMedium,
					Description:    "Reserved concurrency is set to 0, effectively disabling function invocations",
					Recommendation: "Set reserved concurrency above 0 or remove hard limit if not required",
				})
			}

			for _, layerArn := range untrustedLayerARNs(fn.Layers) {
				risks = append(risks, LambdaConfigRisk{
					RiskType:         "UntrustedLambdaLayer",
					FunctionName:     functionName,
					FunctionARN:      functionARN,
					Severity:         SeverityHigh,
					Description:      "Function uses a Lambda layer outside trusted account/vendor allowlist",
					Recommendation:   "Pin to vetted internal or approved vendor layers and review layer publisher trust",
					SupportingDetail: layerArn,
				})
			}

			if hasSnapStartWithSecretLikeEnv(fn.SnapStart, fn.Environment) {
				risks = append(risks, LambdaConfigRisk{
					RiskType:       "SnapStartWithPotentialSecrets",
					FunctionName:   functionName,
					FunctionARN:    functionARN,
					Severity:       SeverityMedium,
					Description:    "SnapStart is enabled while secret-like environment keys are present",
					Recommendation: "Avoid plaintext secret env vars with SnapStart; use Secrets Manager/Parameter Store retrieval at runtime",
				})
			}

			if hasEphemeralStorageEncryptionGap(fn) {
				risks = append(risks, LambdaConfigRisk{
					RiskType:         "EphemeralStorageEncryptionNotEnforced",
					FunctionName:     functionName,
					FunctionARN:      functionARN,
					Severity:         SeverityMedium,
					Description:      "Function uses expanded ephemeral /tmp storage without a configured customer-managed KMS key",
					Recommendation:   "Configure a customer-managed KMS key (`KMSKeyArn`) for Lambda data-at-rest controls when using larger ephemeral storage",
					SupportingDetail: fmt.Sprintf("EphemeralStorageMB=%d", aws.ToInt32(fn.EphemeralStorage.Size)),
				})
			}

			urlConfigs, err := s.listFunctionURLConfigs(ctx, functionName)
			if err != nil {
				return nil, err
			}
			for _, urlCfg := range urlConfigs {
				if isUnauthenticatedFunctionURL(urlCfg.AuthType) {
					risks = append(risks, LambdaConfigRisk{
						RiskType:         "FunctionURLWithoutAuth",
						FunctionName:     functionName,
						FunctionARN:      functionARN,
						Severity:         SeverityHigh,
						Description:      "Lambda Function URL allows unauthenticated public access",
						Recommendation:   "Require AWS_IAM auth and place the endpoint behind API Gateway/WAF where possible",
						SupportingDetail: aws.ToString(urlCfg.FunctionUrl),
					})
				}
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

func (s *service) listFunctionURLConfigs(ctx context.Context, functionName string) ([]lambdatypes.FunctionUrlConfig, error) {
	out, err := s.lambdaClient.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{
		FunctionName: aws.String(functionName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list function URL configs for %s: %w", functionName, err)
	}
	return out.FunctionUrlConfigs, nil
}

func (s *service) getVPCConnectivityState(ctx context.Context) (map[string]bool, map[string]bool, error) {
	subnetToRouteTable := map[string]string{}
	natSubnets := map[string]bool{}
	subnetsWithEndpoints := map[string]bool{}

	rtPaginator := ec2.NewDescribeRouteTablesPaginator(s.ec2Client, &ec2.DescribeRouteTablesInput{})
	for rtPaginator.HasMorePages() {
		page, err := rtPaginator.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to describe route tables: %w", err)
		}

		for _, rt := range page.RouteTables {
			routeTableID := aws.ToString(rt.RouteTableId)
			hasNATRoute := routeTableHasNATRoute(rt.Routes)
			for _, assoc := range rt.Associations {
				if assoc.SubnetId == nil {
					continue
				}
				subnetID := aws.ToString(assoc.SubnetId)
				subnetToRouteTable[subnetID] = routeTableID
				if hasNATRoute {
					natSubnets[subnetID] = true
				}
			}
		}
	}

	epPaginator := ec2.NewDescribeVpcEndpointsPaginator(s.ec2Client, &ec2.DescribeVpcEndpointsInput{})
	for epPaginator.HasMorePages() {
		page, err := epPaginator.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to describe VPC endpoints: %w", err)
		}
		for _, ep := range page.VpcEndpoints {
			for _, subnetID := range ep.SubnetIds {
				subnetsWithEndpoints[subnetID] = true
			}
			for _, routeTableID := range ep.RouteTableIds {
				for subnetID, rtID := range subnetToRouteTable {
					if rtID == routeTableID {
						subnetsWithEndpoints[subnetID] = true
					}
				}
			}
		}
	}

	return natSubnets, subnetsWithEndpoints, nil
}

func routeTableHasNATRoute(routes []ec2types.Route) bool {
	for _, r := range routes {
		if r.NatGatewayId != nil || r.InstanceId != nil {
			return true
		}
	}
	return false
}

func hasRiskyVPCConfig(fn lambdatypes.FunctionConfiguration, natSubnets, subnetsWithEndpoints map[string]bool) bool {
	if fn.VpcConfig == nil || len(fn.VpcConfig.SubnetIds) == 0 {
		return false
	}
	for _, subnetID := range fn.VpcConfig.SubnetIds {
		if natSubnets[subnetID] || subnetsWithEndpoints[subnetID] {
			return false
		}
	}
	return true
}

func (s *service) hasReservedConcurrencyZero(ctx context.Context, functionName string) (bool, error) {
	out, err := s.lambdaClient.GetFunctionConcurrency(ctx, &lambda.GetFunctionConcurrencyInput{
		FunctionName: aws.String(functionName),
	})
	if err != nil {
		return false, fmt.Errorf("failed to get function concurrency for %s: %w", functionName, err)
	}
	return reservedConcurrencyIsZero(out.ReservedConcurrentExecutions), nil
}

func reservedConcurrencyIsZero(v *int32) bool {
	return v != nil && aws.ToInt32(v) == 0
}

func isUnauthenticatedFunctionURL(authType lambdatypes.FunctionUrlAuthType) bool {
	return strings.EqualFold(string(authType), "NONE")
}

func hasSnapStartWithSecretLikeEnv(snapStart *lambdatypes.SnapStartResponse, env *lambdatypes.EnvironmentResponse) bool {
	if snapStart == nil || snapStart.ApplyOn != lambdatypes.SnapStartApplyOnPublishedVersions {
		return false
	}
	if env == nil || env.Variables == nil {
		return false
	}
	for k := range env.Variables {
		if looksLikeSecretKeyName(k) {
			return true
		}
	}
	return false
}

func hasEphemeralStorageEncryptionGap(fn lambdatypes.FunctionConfiguration) bool {
	// Lambda default /tmp (512 MB) uses AWS-managed encryption by default.
	// Flag explicit expanded ephemeral storage when no customer-managed key is configured.
	if fn.EphemeralStorage == nil {
		return false
	}
	if aws.ToInt32(fn.EphemeralStorage.Size) <= 512 {
		return false
	}
	return strings.TrimSpace(aws.ToString(fn.KMSKeyArn)) == ""
}

func looksLikeSecretKeyName(name string) bool {
	n := strings.ToLower(name)
	indicators := []string{
		"secret",
		"token",
		"apikey",
		"api_key",
		"password",
		"passwd",
		"private_key",
		"access_key",
		"auth",
	}
	for _, token := range indicators {
		if strings.Contains(n, token) {
			return true
		}
	}
	return false
}

func untrustedLayerARNs(layers []lambdatypes.Layer) []string {
	if len(layers) == 0 {
		return nil
	}

	var out []string
	for _, l := range layers {
		layerArn := aws.ToString(l.Arn)
		if layerArn == "" {
			continue
		}
		if hasTrustedLayerPrefix(layerArn) {
			continue
		}
		if isAWSManagedLayer(layerArn) {
			continue
		}
		out = append(out, layerArn)
	}
	sort.Strings(out)
	return out
}

func hasTrustedLayerPrefix(layerArn string) bool {
	for _, trustedPrefix := range defaultLayerAllowlist {
		if strings.HasPrefix(layerArn, trustedPrefix) {
			return true
		}
	}
	return false
}

func isAWSManagedLayer(layerArn string) bool {
	parts := strings.Split(layerArn, ":")
	if len(parts) < 5 {
		return false
	}
	// Account 580247275435 is AWS-managed Lambda Insights publisher.
	if parts[4] == "580247275435" {
		return true
	}
	return false
}
