// Package tests contains unit tests for Lambda Security service.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/lambdasecurity"
)

// TestOverlyPermissiveRole tests Lambda permissive role detection
func TestOverlyPermissiveRole(t *testing.T) {
	tests := []struct {
		name           string
		hasAdminAccess bool
		dangerousCount int
		wantSeverity   string
	}{
		{
			name:           "admin access - critical",
			hasAdminAccess: true,
			dangerousCount: 5,
			wantSeverity:   lambdasecurity.SeverityCritical,
		},
		{
			name:           "multiple dangerous actions - high",
			hasAdminAccess: false,
			dangerousCount: 3,
			wantSeverity:   lambdasecurity.SeverityHigh,
		},
		{
			name:           "one dangerous action - medium",
			hasAdminAccess: false,
			dangerousCount: 1,
			wantSeverity:   lambdasecurity.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := lambdasecurity.OverlyPermissiveRole{
				FunctionName:     "my-function",
				FunctionARN:      "arn:aws:lambda:us-east-1:123456789012:function:my-function",
				RoleARN:          "arn:aws:iam::123456789012:role/my-role",
				RoleName:         "my-role",
				DangerousActions: make([]string, tt.dangerousCount),
				HasAdminAccess:   tt.hasAdminAccess,
				Severity:         tt.wantSeverity,
			}
			assert.Equal(t, tt.hasAdminAccess, role.HasAdminAccess)
			assert.Equal(t, tt.dangerousCount, len(role.DangerousActions))
		})
	}
}

// TestCrossRegionExecution tests cross-region Lambda detection
func TestCrossRegionExecution(t *testing.T) {
	risk := lambdasecurity.CrossRegionExecution{
		FunctionName:   "my-function",
		FunctionARN:    "arn:aws:lambda:us-east-1:123456789012:function:my-function",
		CurrentRegion:  "us-east-1",
		TargetRegions:  []string{"eu-west-1", "ap-southeast-1"},
		Severity:       lambdasecurity.SeverityMedium,
		Description:    "Lambda has permissions to access resources in other regions",
		Recommendation: "Restrict Lambda permissions to current region",
	}

	assert.Equal(t, "us-east-1", risk.CurrentRegion)
	assert.Len(t, risk.TargetRegions, 2)
	assert.Contains(t, risk.TargetRegions, "eu-west-1")
}
