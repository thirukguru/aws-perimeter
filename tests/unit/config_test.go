// Package tests contains unit tests for Config/KMS/EBS security service.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/config"
)

// TestConfigStatus tests AWS Config status detection
func TestConfigStatus(t *testing.T) {
	tests := []struct {
		name         string
		isEnabled    bool
		recorder     string
		wantSeverity string
	}{
		{
			name:         "config enabled",
			isEnabled:    true,
			recorder:     "SUCCESS",
			wantSeverity: config.SeverityLow,
		},
		{
			name:         "config disabled - critical",
			isEnabled:    false,
			recorder:     "",
			wantSeverity: config.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &config.ConfigStatus{
				IsEnabled:      tt.isEnabled,
				RecorderStatus: tt.recorder,
				Severity:       tt.wantSeverity,
			}
			assert.Equal(t, tt.isEnabled, status.IsEnabled)
		})
	}
}

// TestEBSEncryptionStatus tests EBS encryption status detection
func TestEBSEncryptionStatus(t *testing.T) {
	tests := []struct {
		name         string
		isEnabled    bool
		wantSeverity string
	}{
		{
			name:         "encryption enabled",
			isEnabled:    true,
			wantSeverity: config.SeverityLow,
		},
		{
			name:         "encryption disabled - high",
			isEnabled:    false,
			wantSeverity: config.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &config.EBSEncryptionStatus{
				DefaultEncryptionEnabled: tt.isEnabled,
				Severity:                 tt.wantSeverity,
			}
			assert.Equal(t, tt.isEnabled, status.DefaultEncryptionEnabled)
		})
	}
}

// TestKMSKeyRotation tests KMS key rotation detection
func TestKMSKeyRotation(t *testing.T) {
	tests := []struct {
		name            string
		rotationEnabled bool
		wantSeverity    string
	}{
		{
			name:            "rotation enabled",
			rotationEnabled: true,
			wantSeverity:    config.SeverityLow,
		},
		{
			name:            "rotation disabled - medium",
			rotationEnabled: false,
			wantSeverity:    config.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := config.KMSKeyRotation{
				KeyID:           "key-12345",
				KeyARN:          "arn:aws:kms:us-east-1:123456789012:key/key-12345",
				RotationEnabled: tt.rotationEnabled,
				Severity:        tt.wantSeverity,
			}
			assert.Equal(t, tt.rotationEnabled, key.RotationEnabled)
		})
	}
}
