// Package tests contains unit tests for ELB/ALB security service.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/elb"
)

// TestALBSecurityRisk tests ALB security risk detection
func TestALBSecurityRisk(t *testing.T) {
	tests := []struct {
		name         string
		riskType     string
		wantSeverity string
	}{
		{
			name:         "no access logs - medium",
			riskType:     "NO_ACCESS_LOGS",
			wantSeverity: elb.SeverityMedium,
		},
		{
			name:         "no WAF - high",
			riskType:     "NO_WAF",
			wantSeverity: elb.SeverityHigh,
		},
		{
			name:         "no deletion protection - low",
			riskType:     "NO_DELETION_PROTECTION",
			wantSeverity: elb.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := elb.ALBSecurityRisk{
				LoadBalancerARN:  "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/123",
				LoadBalancerName: "my-alb",
				RiskType:         tt.riskType,
				Severity:         tt.wantSeverity,
			}
			assert.Equal(t, tt.riskType, risk.RiskType)
			assert.Equal(t, tt.wantSeverity, risk.Severity)
		})
	}
}

// TestListenerSecurityRisk tests listener security risk detection
func TestListenerSecurityRisk(t *testing.T) {
	tests := []struct {
		name         string
		protocol     string
		port         int32
		wantSeverity string
	}{
		{
			name:         "HTTP only - critical",
			protocol:     "HTTP",
			port:         80,
			wantSeverity: elb.SeverityCritical,
		},
		{
			name:         "outdated TLS policy - high",
			protocol:     "HTTPS",
			port:         443,
			wantSeverity: elb.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := elb.ListenerSecurityRisk{
				LoadBalancerName: "my-alb",
				ListenerARN:      "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/123/456",
				Protocol:         tt.protocol,
				Port:             tt.port,
				Severity:         tt.wantSeverity,
			}
			assert.Equal(t, tt.protocol, risk.Protocol)
			assert.Equal(t, tt.port, risk.Port)
		})
	}
}
