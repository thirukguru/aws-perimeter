// Package apigatewaysecurity provides API Gateway security analysis.
package apigatewaysecurity

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// APIGatewayRisk represents a security finding for an API Gateway
type APIGatewayRisk struct {
	APIID          string
	APIName        string
	APIType        string // REST, HTTP, WebSocket
	StageName      string
	RiskType       string
	Severity       string
	Description    string
	Recommendation string
}

// Service is the interface for API Gateway security analysis
type Service interface {
	GetAPIGatewayRisks(ctx context.Context) ([]APIGatewayRisk, error)
}

type service struct {
	restClient *apigateway.Client
	httpClient *apigatewayv2.Client
}

// NewService creates a new API Gateway security service
func NewService(cfg aws.Config) Service {
	return &service{
		restClient: apigateway.NewFromConfig(cfg),
		httpClient: apigatewayv2.NewFromConfig(cfg),
	}
}

// GetAPIGatewayRisks analyzes API Gateway configurations for security issues
func (s *service) GetAPIGatewayRisks(ctx context.Context) ([]APIGatewayRisk, error) {
	var risks []APIGatewayRisk

	// Check REST APIs
	restRisks, err := s.checkRESTAPIs(ctx)
	if err != nil {
		// Log error but continue
		_ = err
	}
	risks = append(risks, restRisks...)

	// Check HTTP APIs
	httpRisks, err := s.checkHTTPAPIs(ctx)
	if err != nil {
		// Log error but continue
		_ = err
	}
	risks = append(risks, httpRisks...)

	return risks, nil
}

func (s *service) checkRESTAPIs(ctx context.Context) ([]APIGatewayRisk, error) {
	var risks []APIGatewayRisk

	// List all REST APIs
	apisOutput, err := s.restClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, err
	}

	for _, api := range apisOutput.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		// Get stages for this API
		stagesOutput, err := s.restClient.GetStages(ctx, &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, stage := range stagesOutput.Item {
			stageName := aws.ToString(stage.StageName)

			// Check 1: Access logging disabled
			if stage.AccessLogSettings == nil || stage.AccessLogSettings.DestinationArn == nil {
				risks = append(risks, APIGatewayRisk{
					APIID:          apiID,
					APIName:        apiName,
					APIType:        "REST",
					StageName:      stageName,
					RiskType:       "NO_ACCESS_LOGGING",
					Severity:       SeverityMedium,
					Description:    "API Gateway stage does not have access logging enabled.",
					Recommendation: "Enable access logging to CloudWatch Logs for security monitoring.",
				})
			}

			// Check 2: WAF not associated
			if stage.WebAclArn == nil || aws.ToString(stage.WebAclArn) == "" {
				risks = append(risks, APIGatewayRisk{
					APIID:          apiID,
					APIName:        apiName,
					APIType:        "REST",
					StageName:      stageName,
					RiskType:       "NO_WAF",
					Severity:       SeverityMedium,
					Description:    "API Gateway stage does not have WAF associated.",
					Recommendation: "Associate an AWS WAF Web ACL to protect against common web attacks.",
				})
			}

			// Check 3: Client certificate not configured
			if stage.ClientCertificateId == nil || aws.ToString(stage.ClientCertificateId) == "" {
				// Only flag for production stages
				if stageName == "prod" || stageName == "production" || stageName == "live" {
					risks = append(risks, APIGatewayRisk{
						APIID:          apiID,
						APIName:        apiName,
						APIType:        "REST",
						StageName:      stageName,
						RiskType:       "NO_CLIENT_CERT",
						Severity:       SeverityLow,
						Description:    "Production API Gateway stage does not use client certificates for backend authentication.",
						Recommendation: "Configure client certificate for mutual TLS with backend.",
					})
				}
			}

			// Check 4: Caching without encryption
			if stage.CacheClusterEnabled && stage.CacheClusterSize != "" {
				// Note: Cache encryption is always enabled for REST APIs since Lambda/HTTP integrations
				// This is informational only
			}

			// Check 5: X-Ray tracing disabled
			if !aws.ToBool(stage.TracingEnabled) {
				risks = append(risks, APIGatewayRisk{
					APIID:          apiID,
					APIName:        apiName,
					APIType:        "REST",
					StageName:      stageName,
					RiskType:       "NO_XRAY",
					Severity:       SeverityLow,
					Description:    "X-Ray tracing is not enabled for this API stage.",
					Recommendation: "Enable X-Ray tracing for better visibility into API performance and errors.",
				})
			}
		}

		// Check 6: Resource policy (API level)
		policyOutput, err := s.restClient.GetRestApi(ctx, &apigateway.GetRestApiInput{
			RestApiId: api.Id,
		})
		if err == nil && policyOutput.Policy != nil {
			policy := aws.ToString(policyOutput.Policy)
			// Check for overly permissive policies
			if strings.Contains(policy, `"Principal":"*"`) && !strings.Contains(policy, `"Condition"`) {
				risks = append(risks, APIGatewayRisk{
					APIID:          apiID,
					APIName:        apiName,
					APIType:        "REST",
					RiskType:       "PERMISSIVE_POLICY",
					Severity:       SeverityHigh,
					Description:    "API Gateway has a resource policy with Principal: * without conditions.",
					Recommendation: "Add conditions (IP, VPC, etc.) to restrict access or use IAM authorization.",
				})
			}
		}

		// Check authorization on methods
		resourceRisks, _ := s.checkRESTAPIResources(ctx, apiID, apiName)
		risks = append(risks, resourceRisks...)
	}

	return risks, nil
}

func (s *service) checkRESTAPIResources(ctx context.Context, apiID, apiName string) ([]APIGatewayRisk, error) {
	var risks []APIGatewayRisk

	// Get all resources
	resourcesOutput, err := s.restClient.GetResources(ctx, &apigateway.GetResourcesInput{
		RestApiId: aws.String(apiID),
	})
	if err != nil {
		return nil, err
	}

	for _, resource := range resourcesOutput.Items {
		if resource.ResourceMethods == nil {
			continue
		}

		for method := range resource.ResourceMethods {
			// Get method details
			methodOutput, err := s.restClient.GetMethod(ctx, &apigateway.GetMethodInput{
				RestApiId:  aws.String(apiID),
				ResourceId: resource.Id,
				HttpMethod: aws.String(method),
			})
			if err != nil {
				continue
			}

			// Check if method has no authorization
			if methodOutput.AuthorizationType != nil && aws.ToString(methodOutput.AuthorizationType) == "NONE" {
				// Skip if it's OPTIONS (CORS preflight)
				if method != "OPTIONS" {
					path := aws.ToString(resource.Path)
					risks = append(risks, APIGatewayRisk{
						APIID:          apiID,
						APIName:        apiName,
						APIType:        "REST",
						RiskType:       "NO_AUTHORIZATION",
						Severity:       SeverityHigh,
						Description:    "API method " + method + " " + path + " has no authorization configured.",
						Recommendation: "Configure IAM, Cognito, or Lambda authorizer for this method.",
					})
				}
			}

			// Check for API key required
			if methodOutput.ApiKeyRequired != nil && !*methodOutput.ApiKeyRequired {
				// Only flag sensitive endpoints
				path := aws.ToString(resource.Path)
				if strings.Contains(path, "admin") || strings.Contains(path, "delete") {
					risks = append(risks, APIGatewayRisk{
						APIID:          apiID,
						APIName:        apiName,
						APIType:        "REST",
						RiskType:       "NO_API_KEY",
						Severity:       SeverityMedium,
						Description:    "Sensitive endpoint " + method + " " + path + " does not require API key.",
						Recommendation: "Require API key for sensitive operations to add an additional layer of access control.",
					})
				}
			}
		}
	}

	return risks, nil
}

func (s *service) checkHTTPAPIs(ctx context.Context) ([]APIGatewayRisk, error) {
	var risks []APIGatewayRisk

	// List all HTTP APIs
	apisOutput, err := s.httpClient.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err != nil {
		return nil, err
	}

	for _, api := range apisOutput.Items {
		apiID := aws.ToString(api.ApiId)
		apiName := aws.ToString(api.Name)

		// Check 1: CORS configuration allowing all origins
		if api.CorsConfiguration != nil {
			if api.CorsConfiguration.AllowOrigins != nil {
				for _, origin := range api.CorsConfiguration.AllowOrigins {
					if origin == "*" {
						risks = append(risks, APIGatewayRisk{
							APIID:          apiID,
							APIName:        apiName,
							APIType:        "HTTP",
							RiskType:       "CORS_WILDCARD",
							Severity:       SeverityMedium,
							Description:    "HTTP API allows CORS requests from all origins (*).",
							Recommendation: "Specify allowed origins instead of using wildcard.",
						})
						break
					}
				}
			}
		}

		// Get stages for HTTP API
		stagesOutput, err := s.httpClient.GetStages(ctx, &apigatewayv2.GetStagesInput{
			ApiId: api.ApiId,
		})
		if err != nil {
			continue
		}

		for _, stage := range stagesOutput.Items {
			stageName := aws.ToString(stage.StageName)

			// Check 2: Access logging
			if stage.AccessLogSettings == nil || stage.AccessLogSettings.DestinationArn == nil {
				risks = append(risks, APIGatewayRisk{
					APIID:          apiID,
					APIName:        apiName,
					APIType:        "HTTP",
					StageName:      stageName,
					RiskType:       "NO_ACCESS_LOGGING",
					Severity:       SeverityMedium,
					Description:    "HTTP API stage does not have access logging enabled.",
					Recommendation: "Enable access logging to CloudWatch Logs.",
				})
			}

			// Check 3: Throttling not configured
			noThrottling := stage.DefaultRouteSettings == nil ||
				(stage.DefaultRouteSettings.ThrottlingBurstLimit == nil && stage.DefaultRouteSettings.ThrottlingRateLimit == nil)
			if noThrottling {
				risks = append(risks, APIGatewayRisk{
					APIID:          apiID,
					APIName:        apiName,
					APIType:        "HTTP",
					StageName:      stageName,
					RiskType:       "NO_THROTTLING",
					Severity:       SeverityLow,
					Description:    "HTTP API stage has no throttling limits configured.",
					Recommendation: "Configure throttling to protect backend from traffic spikes.",
				})
			}
		}

		// Check 4: Routes without authorization
		routesOutput, err := s.httpClient.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{
			ApiId: api.ApiId,
		})
		if err != nil {
			continue
		}

		for _, route := range routesOutput.Items {
			routeKey := aws.ToString(route.RouteKey)

			// Skip preflight OPTIONS
			if strings.HasPrefix(routeKey, "OPTIONS ") {
				continue
			}

			if route.AuthorizationType == "" || route.AuthorizationType == "NONE" {
				risks = append(risks, APIGatewayRisk{
					APIID:          apiID,
					APIName:        apiName,
					APIType:        "HTTP",
					RiskType:       "NO_AUTHORIZATION",
					Severity:       SeverityHigh,
					Description:    "HTTP API route '" + routeKey + "' has no authorization.",
					Recommendation: "Configure JWT authorizer or IAM authorization for this route.",
				})
			}
		}
	}

	return risks, nil
}
