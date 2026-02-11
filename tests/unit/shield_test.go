// Package tests contains unit tests for Shield/WAF security service.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/shield"
)

// TestDDoSProtectionStatus tests Shield protection status
func TestDDoSProtectionStatus(t *testing.T) {
	tests := []struct {
		name         string
		isAdvanced   bool
		subsState    string
		wantSeverity string
	}{
		{
			name:         "shield advanced enabled",
			isAdvanced:   true,
			subsState:    "ACTIVE",
			wantSeverity: shield.SeverityInfo,
		},
		{
			name:         "shield standard only",
			isAdvanced:   false,
			subsState:    "INACTIVE",
			wantSeverity: shield.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &shield.DDoSProtectionStatus{
				ShieldAdvancedEnabled: tt.isAdvanced,
				SubscriptionState:     tt.subsState,
				Severity:              tt.wantSeverity,
			}
			assert.Equal(t, tt.isAdvanced, status.ShieldAdvancedEnabled)
			assert.Equal(t, tt.subsState, status.SubscriptionState)
		})
	}
}

// TestUnprotectedResource tests unprotected resource detection
func TestUnprotectedResource(t *testing.T) {
	resource := shield.UnprotectedResource{
		ResourceARN:    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/123",
		ResourceType:   "ALB",
		Severity:       shield.SeverityMedium,
		Description:    "Internet-facing ALB without Shield protection",
		Recommendation: "Add Shield Advanced protection",
	}

	assert.Contains(t, resource.ResourceARN, "loadbalancer")
	assert.Equal(t, "ALB", resource.ResourceType)
	assert.Equal(t, shield.SeverityMedium, resource.Severity)
}

// TestWAFStatus tests WAF status detection
func TestWAFStatus(t *testing.T) {
	tests := []struct {
		name         string
		ruleCount    int
		wantSeverity string
	}{
		{
			name:         "no rules - high severity",
			ruleCount:    0,
			wantSeverity: shield.SeverityHigh,
		},
		{
			name:         "has rules - info severity",
			ruleCount:    5,
			wantSeverity: shield.SeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := shield.WAFStatus{
				WebACLName: "my-acl",
				WebACLARN:  "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/123",
				RuleCount:  tt.ruleCount,
				Severity:   tt.wantSeverity,
			}
			assert.Equal(t, tt.ruleCount, status.RuleCount)
		})
	}
}
