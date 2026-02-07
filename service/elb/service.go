// Package elb provides ELB/ALB security analysis.
package elb

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// ALBSecurityRisk represents a security issue with an ALB
type ALBSecurityRisk struct {
	LoadBalancerARN  string
	LoadBalancerName string
	RiskType         string
	Severity         string
	Description      string
	Recommendation   string
}

// ListenerSecurityRisk represents a listener security issue
type ListenerSecurityRisk struct {
	LoadBalancerName string
	ListenerARN      string
	Protocol         string
	Port             int32
	Severity         string
	Description      string
	Recommendation   string
}

type service struct {
	client *elasticloadbalancingv2.Client
}

// Service is the interface for ELB security analysis
type Service interface {
	GetALBSecurityRisks(ctx context.Context) ([]ALBSecurityRisk, error)
	GetListenerSecurityRisks(ctx context.Context) ([]ListenerSecurityRisk, error)
}

// NewService creates a new ELB service
func NewService(cfg aws.Config) Service {
	return &service{
		client: elasticloadbalancingv2.NewFromConfig(cfg),
	}
}

// GetALBSecurityRisks checks ALB configurations for security issues
func (s *service) GetALBSecurityRisks(ctx context.Context) ([]ALBSecurityRisk, error) {
	var risks []ALBSecurityRisk

	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(s.client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe load balancers: %w", err)
		}

		for _, lb := range page.LoadBalancers {
			// Check if internet-facing
			if lb.Scheme == types.LoadBalancerSchemeEnumInternetFacing {
				// Check for access logs
				attrs, err := s.client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
					LoadBalancerArn: lb.LoadBalancerArn,
				})
				if err != nil {
					continue
				}

				accessLogsEnabled := false
				deletionProtection := false
				wafEnabled := false

				for _, attr := range attrs.Attributes {
					key := aws.ToString(attr.Key)
					value := aws.ToString(attr.Value)

					switch key {
					case "access_logs.s3.enabled":
						accessLogsEnabled = value == "true"
					case "deletion_protection.enabled":
						deletionProtection = value == "true"
					case "waf.fail_open.enabled":
						// If this attribute exists, WAF is likely configured
						wafEnabled = true
					}
				}

				// Report missing access logs
				if !accessLogsEnabled {
					risks = append(risks, ALBSecurityRisk{
						LoadBalancerARN:  aws.ToString(lb.LoadBalancerArn),
						LoadBalancerName: aws.ToString(lb.LoadBalancerName),
						RiskType:         "NO_ACCESS_LOGS",
						Severity:         SeverityMedium,
						Description:      "ALB access logs not enabled - no visibility into traffic",
						Recommendation:   "Enable access logs to S3 for security monitoring",
					})
				}

				// Report missing deletion protection
				if !deletionProtection {
					risks = append(risks, ALBSecurityRisk{
						LoadBalancerARN:  aws.ToString(lb.LoadBalancerArn),
						LoadBalancerName: aws.ToString(lb.LoadBalancerName),
						RiskType:         "NO_DELETION_PROTECTION",
						Severity:         SeverityLow,
						Description:      "Deletion protection not enabled",
						Recommendation:   "Enable deletion protection for production ALBs",
					})
				}

				// Report missing WAF (only for internet-facing)
				if !wafEnabled {
					risks = append(risks, ALBSecurityRisk{
						LoadBalancerARN:  aws.ToString(lb.LoadBalancerArn),
						LoadBalancerName: aws.ToString(lb.LoadBalancerName),
						RiskType:         "NO_WAF",
						Severity:         SeverityHigh,
						Description:      "Internet-facing ALB without WAF protection",
						Recommendation:   "Associate AWS WAF web ACL for application-layer protection",
					})
				}
			}
		}
	}

	return risks, nil
}

// GetListenerSecurityRisks checks ALB listener configurations
func (s *service) GetListenerSecurityRisks(ctx context.Context) ([]ListenerSecurityRisk, error) {
	var risks []ListenerSecurityRisk

	// Get all load balancers
	lbs, err := s.client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe load balancers: %w", err)
	}

	for _, lb := range lbs.LoadBalancers {
		// Get listeners for this LB
		listeners, err := s.client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
			LoadBalancerArn: lb.LoadBalancerArn,
		})
		if err != nil {
			continue
		}

		hasHTTPS := false
		hasHTTP := false

		for _, listener := range listeners.Listeners {
			if listener.Protocol == types.ProtocolEnumHttps {
				hasHTTPS = true

				// Check for outdated TLS policy
				if listener.SslPolicy != nil {
					policy := aws.ToString(listener.SslPolicy)
					if isOutdatedTLSPolicy(policy) {
						risks = append(risks, ListenerSecurityRisk{
							LoadBalancerName: aws.ToString(lb.LoadBalancerName),
							ListenerARN:      aws.ToString(listener.ListenerArn),
							Protocol:         string(listener.Protocol),
							Port:             aws.ToInt32(listener.Port),
							Severity:         SeverityHigh,
							Description:      fmt.Sprintf("Outdated TLS policy: %s", policy),
							Recommendation:   "Use TLS 1.2+ policy (ELBSecurityPolicy-TLS13-1-2-2021-06 or newer)",
						})
					}
				}
			}

			if listener.Protocol == types.ProtocolEnumHttp {
				hasHTTP = true
			}
		}

		// Check for HTTP without HTTPS redirect (internet-facing only)
		if lb.Scheme == types.LoadBalancerSchemeEnumInternetFacing && hasHTTP && !hasHTTPS {
			risks = append(risks, ListenerSecurityRisk{
				LoadBalancerName: aws.ToString(lb.LoadBalancerName),
				Protocol:         "HTTP",
				Severity:         SeverityCritical,
				Description:      "Internet-facing ALB with HTTP only - no TLS encryption",
				Recommendation:   "Configure HTTPS listener with valid certificate",
			})
		}
	}

	return risks, nil
}

func isOutdatedTLSPolicy(policy string) bool {
	outdatedPolicies := []string{
		"ELBSecurityPolicy-2016-08",
		"ELBSecurityPolicy-TLS-1-0-2015-04",
		"ELBSecurityPolicy-TLS-1-1-2017-01",
		"ELBSecurityPolicy-2015-05",
	}

	for _, outdated := range outdatedPolicies {
		if policy == outdated {
			return true
		}
	}

	return false
}
