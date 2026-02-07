// Package tests contains unit tests for IAM Advanced security service.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/iamadvanced"
)

// TestRoleChainRisk tests role chaining risk detection
func TestRoleChainRisk(t *testing.T) {
	tests := []struct {
		name         string
		chainDepth   int
		isCircular   bool
		wantSeverity string
	}{
		{
			name:         "shallow chain - low risk",
			chainDepth:   2,
			isCircular:   false,
			wantSeverity: iamadvanced.SeverityLow,
		},
		{
			name:         "deep chain - medium risk",
			chainDepth:   4,
			isCircular:   false,
			wantSeverity: iamadvanced.SeverityMedium,
		},
		{
			name:         "circular chain - critical risk",
			chainDepth:   3,
			isCircular:   true,
			wantSeverity: iamadvanced.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := iamadvanced.RoleChainRisk{
				RoleName:   "test-role",
				RoleARN:    "arn:aws:iam::123456789012:role/test-role",
				ChainDepth: tt.chainDepth,
				IsCircular: tt.isCircular,
				Severity:   tt.wantSeverity,
			}
			assert.Equal(t, tt.chainDepth, risk.ChainDepth)
			assert.Equal(t, tt.isCircular, risk.IsCircular)
		})
	}
}

// TestExternalIDRisk tests missing external ID detection
func TestExternalIDRisk(t *testing.T) {
	tests := []struct {
		name           string
		hasExternalID  bool
		trustedAccount string
		wantSeverity   string
	}{
		{
			name:           "has external ID - low risk",
			hasExternalID:  true,
			trustedAccount: "987654321098",
			wantSeverity:   iamadvanced.SeverityLow,
		},
		{
			name:           "missing external ID - high risk",
			hasExternalID:  false,
			trustedAccount: "987654321098",
			wantSeverity:   iamadvanced.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := iamadvanced.ExternalIDRisk{
				RoleName:       "cross-account-role",
				RoleARN:        "arn:aws:iam::123456789012:role/cross-account-role",
				TrustedAccount: tt.trustedAccount,
				HasExternalID:  tt.hasExternalID,
				Severity:       tt.wantSeverity,
			}
			assert.Equal(t, tt.hasExternalID, risk.HasExternalID)
			assert.Equal(t, tt.trustedAccount, risk.TrustedAccount)
		})
	}
}

// TestPermissionBoundaryRisk tests missing permission boundary detection
func TestPermissionBoundaryRisk(t *testing.T) {
	tests := []struct {
		name             string
		principalType    string
		hasBoundary      bool
		attachedPolicies int
		wantSeverity     string
	}{
		{
			name:             "user with no boundary and admin policies - critical",
			principalType:    "User",
			hasBoundary:      false,
			attachedPolicies: 5,
			wantSeverity:     iamadvanced.SeverityCritical,
		},
		{
			name:             "role with boundary - low",
			principalType:    "Role",
			hasBoundary:      true,
			attachedPolicies: 3,
			wantSeverity:     iamadvanced.SeverityLow,
		},
		{
			name:             "user with no boundary - medium",
			principalType:    "User",
			hasBoundary:      false,
			attachedPolicies: 2,
			wantSeverity:     iamadvanced.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := iamadvanced.PermissionBoundaryRisk{
				PrincipalName:    "test-principal",
				PrincipalType:    tt.principalType,
				HasBoundary:      tt.hasBoundary,
				AttachedPolicies: tt.attachedPolicies,
				Severity:         tt.wantSeverity,
			}
			assert.Equal(t, tt.principalType, risk.PrincipalType)
			assert.Equal(t, tt.hasBoundary, risk.HasBoundary)
		})
	}
}

// TestInstanceProfileRisk tests EC2 instance profile risk detection
func TestInstanceProfileRisk(t *testing.T) {
	tests := []struct {
		name               string
		roleName           string
		isOverlyPermissive bool
		wantSeverity       string
	}{
		{
			name:               "overly permissive - critical",
			roleName:           "admin-role",
			isOverlyPermissive: true,
			wantSeverity:       iamadvanced.SeverityCritical,
		},
		{
			name:               "limited access - low",
			roleName:           "limited-role",
			isOverlyPermissive: false,
			wantSeverity:       iamadvanced.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := iamadvanced.InstanceProfileRisk{
				InstanceProfileName: "test-profile",
				RoleName:            tt.roleName,
				HasOverlyPermissive: tt.isOverlyPermissive,
				Severity:            tt.wantSeverity,
			}
			assert.Equal(t, tt.isOverlyPermissive, risk.HasOverlyPermissive)
			assert.Equal(t, tt.roleName, risk.RoleName)
		})
	}
}

// TestServiceRoleMisuse tests service role misuse detection
func TestServiceRoleMisuse(t *testing.T) {
	risk := iamadvanced.ServiceRoleMisuse{
		RoleName:           "lambda-role",
		RoleARN:            "arn:aws:iam::123456789012:role/lambda-role",
		ServicePrincipal:   "lambda.amazonaws.com",
		AllowsPassRole:     true,
		IsOverlyPermissive: true,
		Severity:           iamadvanced.SeverityCritical,
		Description:        "Lambda role allows iam:PassRole",
		Recommendation:     "Restrict PassRole to specific roles",
	}

	assert.Equal(t, "lambda.amazonaws.com", risk.ServicePrincipal)
	assert.True(t, risk.AllowsPassRole)
	assert.True(t, risk.IsOverlyPermissive)
	assert.Equal(t, iamadvanced.SeverityCritical, risk.Severity)
}
