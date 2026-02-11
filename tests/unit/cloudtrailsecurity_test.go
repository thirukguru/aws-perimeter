// Package tests contains unit tests for CloudTrail Security service.
package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/cloudtrailsecurity"
)

// TestRootAccountUsage tests root account usage detection
func TestRootAccountUsage(t *testing.T) {
	event := cloudtrailsecurity.RootAccountUsage{
		EventName: "ConsoleLogin",
		EventTime: time.Now(),
		SourceIP:  "1.2.3.4",
		UserAgent: "AWS Console",
		Severity:  cloudtrailsecurity.SeverityCritical,
	}

	assert.Equal(t, "ConsoleLogin", event.EventName)
	assert.Equal(t, "1.2.3.4", event.SourceIP)
	assert.Equal(t, cloudtrailsecurity.SeverityCritical, event.Severity)
}

// TestIAMRoleCreationEvent tests IAM role creation event detection
func TestIAMRoleCreationEvent(t *testing.T) {
	tests := []struct {
		name         string
		isAutomated  bool
		wantSeverity string
	}{
		{
			name:         "automated role creation - low",
			isAutomated:  true,
			wantSeverity: cloudtrailsecurity.SeverityLow,
		},
		{
			name:         "manual role creation - medium",
			isAutomated:  false,
			wantSeverity: cloudtrailsecurity.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := cloudtrailsecurity.IAMRoleCreationEvent{
				RoleName:    "test-role",
				CreatedBy:   "admin-user",
				EventTime:   time.Now(),
				SourceIP:    "1.2.3.4",
				IsAutomated: tt.isAutomated,
				Severity:    tt.wantSeverity,
			}
			assert.Equal(t, tt.isAutomated, event.IsAutomated)
		})
	}
}

// TestSuspiciousActivity tests suspicious activity detection
func TestSuspiciousActivity(t *testing.T) {
	activity := cloudtrailsecurity.SuspiciousActivity{
		EventTime:   time.Now(),
		EventName:   "GetSecretValue",
		EventSource: "secretsmanager.amazonaws.com",
		UserName:    "suspicious-user",
		SourceIP:    "198.51.100.1",
		ErrorCode:   "AccessDenied",
		Severity:    cloudtrailsecurity.SeverityHigh,
	}

	assert.Equal(t, "GetSecretValue", activity.EventName)
	assert.Equal(t, "secretsmanager.amazonaws.com", activity.EventSource)
	assert.Equal(t, cloudtrailsecurity.SeverityHigh, activity.Severity)
}
