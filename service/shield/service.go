// Package shield provides AWS Shield and WAF security analysis.
package shield

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/shield"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// DDoSProtectionStatus represents Shield protection status
type DDoSProtectionStatus struct {
	ShieldAdvancedEnabled bool
	SubscriptionState     string
	Severity              string
	Recommendation        string
}

// ProtectedResource represents a resource protected by Shield Advanced
type ProtectedResource struct {
	ResourceARN  string
	ResourceType string
	ProtectionID string
}

// UnprotectedResource represents a high-value resource without DDoS protection
type UnprotectedResource struct {
	ResourceARN    string
	ResourceType   string
	Severity       string
	Description    string
	Recommendation string
}

// WAFStatus represents WAF configuration status
type WAFStatus struct {
	WebACLName    string
	WebACLARN     string
	RuleCount     int
	AssociatedALB []string
	Severity      string
}

type service struct {
	shieldClient *shield.Client
	wafClient    *wafv2.Client
}

// Service is the interface for Shield/DDoS analysis
type Service interface {
	GetDDoSProtectionStatus(ctx context.Context) (*DDoSProtectionStatus, error)
	GetUnprotectedResources(ctx context.Context) ([]UnprotectedResource, error)
	GetWAFStatus(ctx context.Context) ([]WAFStatus, error)
}

// NewService creates a new Shield/WAF service
func NewService(cfg aws.Config) Service {
	return &service{
		shieldClient: shield.NewFromConfig(cfg),
		wafClient:    wafv2.NewFromConfig(cfg),
	}
}

// GetDDoSProtectionStatus checks if Shield Advanced is enabled
func (s *service) GetDDoSProtectionStatus(ctx context.Context) (*DDoSProtectionStatus, error) {
	sub, err := s.shieldClient.GetSubscriptionState(ctx, &shield.GetSubscriptionStateInput{})
	if err != nil {
		// Shield Advanced not available or not subscribed
		return &DDoSProtectionStatus{
			ShieldAdvancedEnabled: false,
			SubscriptionState:     "INACTIVE",
			Severity:              SeverityMedium,
			Recommendation:        "Consider enabling AWS Shield Advanced for enhanced DDoS protection",
		}, nil
	}

	isEnabled := string(sub.SubscriptionState) == "ACTIVE"

	status := &DDoSProtectionStatus{
		ShieldAdvancedEnabled: isEnabled,
		SubscriptionState:     string(sub.SubscriptionState),
	}

	if isEnabled {
		status.Severity = SeverityInfo
		status.Recommendation = "Shield Advanced is enabled"
	} else {
		status.Severity = SeverityMedium
		status.Recommendation = "Shield Advanced is not active - only basic DDoS protection available"
	}

	return status, nil
}

// GetUnprotectedResources finds high-value resources without DDoS protection
func (s *service) GetUnprotectedResources(ctx context.Context) ([]UnprotectedResource, error) {
	var unprotected []UnprotectedResource

	// Check for CloudFront distributions, ALBs, and Route53 hosted zones
	// that should be protected by Shield Advanced
	protections, err := s.shieldClient.ListProtections(ctx, &shield.ListProtectionsInput{})
	if err != nil {
		// Shield not enabled, return empty
		return unprotected, nil
	}

	protectedARNs := make(map[string]bool)
	for _, p := range protections.Protections {
		if p.ResourceArn != nil {
			protectedARNs[*p.ResourceArn] = true
		}
	}

	// Note: In a full implementation, we would list ALBs, CloudFront, etc.
	// and check if they're in the protected list
	// For now, we just report the protection count

	if len(protectedARNs) == 0 {
		unprotected = append(unprotected, UnprotectedResource{
			ResourceARN:    "N/A",
			ResourceType:   "Account",
			Severity:       SeverityMedium,
			Description:    "No resources protected by Shield Advanced",
			Recommendation: "Add Shield Advanced protection to critical resources (ALB, CloudFront, Route53)",
		})
	}

	return unprotected, nil
}

// GetWAFStatus checks WAF web ACL configurations
func (s *service) GetWAFStatus(ctx context.Context) ([]WAFStatus, error) {
	var statuses []WAFStatus

	// List regional web ACLs (for ALB)
	input := &wafv2.ListWebACLsInput{
		Scope: types.ScopeRegional,
	}

	acls, err := s.wafClient.ListWebACLs(ctx, input)
	if err != nil {
		// WAF not configured
		return statuses, nil
	}

	for _, acl := range acls.WebACLs {
		status := WAFStatus{
			WebACLName: aws.ToString(acl.Name),
			WebACLARN:  aws.ToString(acl.ARN),
			Severity:   SeverityInfo,
		}

		// Get ACL details for rule count
		detail, err := s.wafClient.GetWebACL(ctx, &wafv2.GetWebACLInput{
			Id:    acl.Id,
			Name:  acl.Name,
			Scope: types.ScopeRegional,
		})
		if err == nil && detail.WebACL != nil {
			status.RuleCount = len(detail.WebACL.Rules)
			if status.RuleCount == 0 {
				status.Severity = SeverityHigh
			}
		}

		statuses = append(statuses, status)
	}

	if len(statuses) == 0 {
		statuses = append(statuses, WAFStatus{
			WebACLName: "None",
			Severity:   SeverityHigh,
		})
	}

	return statuses, nil
}
