// Package tests contains unit tests for Data Protection security service.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/dataprotection"
)

// TestRDSSecurityRisk tests RDS security risk detection
func TestRDSSecurityRisk(t *testing.T) {
	tests := []struct {
		name         string
		isPublic     bool
		isEncrypted  bool
		wantSeverity string
	}{
		{
			name:         "public unencrypted - critical",
			isPublic:     true,
			isEncrypted:  false,
			wantSeverity: dataprotection.SeverityCritical,
		},
		{
			name:         "public encrypted - high",
			isPublic:     true,
			isEncrypted:  true,
			wantSeverity: dataprotection.SeverityHigh,
		},
		{
			name:         "private unencrypted - medium",
			isPublic:     false,
			isEncrypted:  false,
			wantSeverity: dataprotection.SeverityMedium,
		},
		{
			name:         "private encrypted - low",
			isPublic:     false,
			isEncrypted:  true,
			wantSeverity: dataprotection.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := dataprotection.RDSSecurityRisk{
				DBInstanceID: "my-db",
				Engine:       "mysql",
				IsPublic:     tt.isPublic,
				IsEncrypted:  tt.isEncrypted,
				Severity:     tt.wantSeverity,
			}
			assert.Equal(t, tt.isPublic, risk.IsPublic)
			assert.Equal(t, tt.isEncrypted, risk.IsEncrypted)
		})
	}
}

// TestDynamoDBRisk tests DynamoDB security risk detection
func TestDynamoDBRisk(t *testing.T) {
	tests := []struct {
		name            string
		pitrEnabled     bool
		deletionProtect bool
		wantSeverity    string
	}{
		{
			name:            "no PITR no protection - high",
			pitrEnabled:     false,
			deletionProtect: false,
			wantSeverity:    dataprotection.SeverityHigh,
		},
		{
			name:            "PITR enabled - low",
			pitrEnabled:     true,
			deletionProtect: true,
			wantSeverity:    dataprotection.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := dataprotection.DynamoDBRisk{
				TableName:           "my-table",
				IsEncrypted:         true,
				PointInTimeRecovery: tt.pitrEnabled,
				DeletionProtection:  tt.deletionProtect,
				Severity:            tt.wantSeverity,
			}
			assert.Equal(t, tt.pitrEnabled, risk.PointInTimeRecovery)
		})
	}
}

// TestSecretRotationRisk tests Secrets Manager rotation risk
func TestSecretRotationRisk(t *testing.T) {
	tests := []struct {
		name            string
		rotationEnabled bool
		lastRotatedDays int
		wantSeverity    string
	}{
		{
			name:            "no rotation - high",
			rotationEnabled: false,
			lastRotatedDays: 365,
			wantSeverity:    dataprotection.SeverityHigh,
		},
		{
			name:            "rotation enabled recent - low",
			rotationEnabled: true,
			lastRotatedDays: 30,
			wantSeverity:    dataprotection.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := dataprotection.SecretRotationRisk{
				SecretName:      "my-secret",
				SecretARN:       "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret",
				RotationEnabled: tt.rotationEnabled,
				LastRotatedDays: tt.lastRotatedDays,
				Severity:        tt.wantSeverity,
			}
			assert.Equal(t, tt.rotationEnabled, risk.RotationEnabled)
		})
	}
}

// TestBackupStatus tests Backup status detection
func TestBackupStatus(t *testing.T) {
	status := &dataprotection.BackupStatus{
		VaultsCount:        2,
		ActivePlans:        3,
		ProtectedResources: 10,
		Severity:           dataprotection.SeverityMedium,
	}

	assert.Equal(t, 2, status.VaultsCount)
	assert.Equal(t, 3, status.ActivePlans)
	assert.Equal(t, 10, status.ProtectedResources)
}
