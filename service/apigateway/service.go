// Package apigateway provides API Gateway security analysis.
package apigateway

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// APIRisk represents a security risk in an API
type APIRisk struct {
	APIID          string
	APIName        string
	ProtocolType   string
	RiskType       string
	Severity       string
	Description    string
	Recommendation string
}

// RateLimitStatus represents rate limiting configuration
type RateLimitStatus struct {
	APIID          string
	APIName        string
	StageID        string
	StageName      string
	HasRateLimit   bool
	RateLimit      int
	BurstLimit     int
	Severity       string
	Recommendation string
}

// AuthorizationStatus represents authorization configuration
type AuthorizationStatus struct {
	APIID          string
	APIName        string
	RouteKey       string
	AuthType       string
	HasAuth        bool
	Severity       string
	Recommendation string
}

type service struct {
	client *apigatewayv2.Client
}

// Service is the interface for API Gateway analysis
type Service interface {
	GetAPIsWithoutRateLimits(ctx context.Context) ([]RateLimitStatus, error)
	GetUnauthorizedRoutes(ctx context.Context) ([]AuthorizationStatus, error)
	GetAPIRisks(ctx context.Context) ([]APIRisk, error)
}

// NewService creates a new API Gateway service
func NewService(cfg aws.Config) Service {
	return &service{
		client: apigatewayv2.NewFromConfig(cfg),
	}
}

// GetAPIsWithoutRateLimits checks for APIs without rate limiting
func (s *service) GetAPIsWithoutRateLimits(ctx context.Context) ([]RateLimitStatus, error) {
	var statuses []RateLimitStatus

	apis, err := s.client.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err != nil {
		return nil, err
	}

	for _, api := range apis.Items {
		// Get stages for this API
		stages, err := s.client.GetStages(ctx, &apigatewayv2.GetStagesInput{
			ApiId: api.ApiId,
		})
		if err != nil {
			continue
		}

		for _, stage := range stages.Items {
			status := RateLimitStatus{
				APIID:     aws.ToString(api.ApiId),
				APIName:   aws.ToString(api.Name),
				StageID:   aws.ToString(stage.StageName),
				StageName: aws.ToString(stage.StageName),
			}

			// Check throttling settings
			if stage.DefaultRouteSettings != nil {
				rateLimit := aws.ToFloat64(stage.DefaultRouteSettings.ThrottlingRateLimit)
				status.HasRateLimit = rateLimit > 0
				status.RateLimit = int(rateLimit)
				status.BurstLimit = int(aws.ToInt32(stage.DefaultRouteSettings.ThrottlingBurstLimit))
			}

			if !status.HasRateLimit {
				status.Severity = SeverityHigh
				status.Recommendation = "Configure rate limiting to prevent DDoS/abuse"
			} else {
				status.Severity = SeverityInfo
				status.Recommendation = "Rate limiting is configured"
			}

			// Only report those without rate limits
			if !status.HasRateLimit {
				statuses = append(statuses, status)
			}
		}
	}

	return statuses, nil
}

// GetUnauthorizedRoutes checks for routes without authorization
func (s *service) GetUnauthorizedRoutes(ctx context.Context) ([]AuthorizationStatus, error) {
	var statuses []AuthorizationStatus

	apis, err := s.client.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err != nil {
		return nil, err
	}

	for _, api := range apis.Items {
		// Get routes for this API
		routes, err := s.client.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{
			ApiId: api.ApiId,
		})
		if err != nil {
			continue
		}

		for _, route := range routes.Items {
			authType := string(route.AuthorizationType)
			hasAuth := route.AuthorizationType != types.AuthorizationTypeNone &&
				route.AuthorizationType != ""

			// Skip if route has authorization
			if hasAuth {
				continue
			}

			statuses = append(statuses, AuthorizationStatus{
				APIID:          aws.ToString(api.ApiId),
				APIName:        aws.ToString(api.Name),
				RouteKey:       aws.ToString(route.RouteKey),
				AuthType:       authType,
				HasAuth:        hasAuth,
				Severity:       SeverityCritical,
				Recommendation: "Add authorization (JWT, IAM, Lambda authorizer)",
			})
		}
	}

	return statuses, nil
}

// GetAPIRisks gets general API security risks
func (s *service) GetAPIRisks(ctx context.Context) ([]APIRisk, error) {
	var risks []APIRisk

	apis, err := s.client.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err != nil {
		return nil, err
	}

	for _, api := range apis.Items {
		// Check for CORS misconfiguration
		if api.CorsConfiguration != nil {
			cors := api.CorsConfiguration
			for _, origin := range cors.AllowOrigins {
				if origin == "*" {
					risks = append(risks, APIRisk{
						APIID:          aws.ToString(api.ApiId),
						APIName:        aws.ToString(api.Name),
						ProtocolType:   string(api.ProtocolType),
						RiskType:       "CORS_WILDCARD",
						Severity:       SeverityMedium,
						Description:    "CORS allows all origins (*)",
						Recommendation: "Restrict CORS to specific domains",
					})
					break
				}
			}
		}

		// Check for HTTP vs HTTPS
		if api.ProtocolType == types.ProtocolTypeHttp {
			// HTTP APIs - check if there's no custom domain (could mean non-HTTPS)
			risks = append(risks, APIRisk{
				APIID:          aws.ToString(api.ApiId),
				APIName:        aws.ToString(api.Name),
				ProtocolType:   string(api.ProtocolType),
				RiskType:       "HTTPS_CHECK",
				Severity:       SeverityInfo,
				Description:    "Verify API uses HTTPS endpoints only",
				Recommendation: "Ensure custom domains use TLS 1.2+",
			})
		}
	}

	return risks, nil
}
