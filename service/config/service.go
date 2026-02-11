// Package config provides AWS Config, KMS, and EBS security analysis.
package config

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// ConfigStatus represents AWS Config enablement status
type ConfigStatus struct {
	IsEnabled       bool
	RecorderStatus  string
	DeliveryChannel string
	Severity        string
	Description     string
	Recommendation  string
}

// EBSEncryptionStatus represents EBS default encryption status
type EBSEncryptionStatus struct {
	DefaultEncryptionEnabled bool
	DefaultKMSKeyID          string
	Region                   string
	Severity                 string
	Description              string
	Recommendation           string
}

// KMSKeyRotation represents KMS key rotation status
type KMSKeyRotation struct {
	KeyID           string
	KeyARN          string
	KeyAlias        string
	RotationEnabled bool
	CreatedDaysAgo  int
	Severity        string
	Description     string
	Recommendation  string
}

type service struct {
	configClient *configservice.Client
	ec2Client    *ec2.Client
	kmsClient    *kms.Client
}

// Service is the interface for Config/KMS/EBS security analysis
type Service interface {
	GetConfigStatus(ctx context.Context) (*ConfigStatus, error)
	GetEBSEncryptionStatus(ctx context.Context) (*EBSEncryptionStatus, error)
	GetKMSKeyRotationStatus(ctx context.Context) ([]KMSKeyRotation, error)
}

// NewService creates a new Config/KMS/EBS service
func NewService(cfg aws.Config) Service {
	return &service{
		configClient: configservice.NewFromConfig(cfg),
		ec2Client:    ec2.NewFromConfig(cfg),
		kmsClient:    kms.NewFromConfig(cfg),
	}
}

// GetConfigStatus checks if AWS Config is enabled
func (s *service) GetConfigStatus(ctx context.Context) (*ConfigStatus, error) {
	status := &ConfigStatus{
		IsEnabled: false,
	}

	// Check for configuration recorders
	recorders, err := s.configClient.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		status.Severity = SeverityCritical
		status.Description = "AWS Config is not enabled"
		status.Recommendation = "Enable AWS Config for resource tracking and compliance"
		return status, nil
	}

	if len(recorders.ConfigurationRecorders) == 0 {
		status.Severity = SeverityCritical
		status.Description = "No AWS Config recorders found"
		status.Recommendation = "Enable AWS Config for resource tracking and compliance"
		return status, nil
	}

	// Check recorder status
	recorderStatus, err := s.configClient.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err == nil && len(recorderStatus.ConfigurationRecordersStatus) > 0 {
		rs := recorderStatus.ConfigurationRecordersStatus[0]
		status.RecorderStatus = string(rs.LastStatus)
		status.IsEnabled = rs.Recording
	}

	// Check delivery channel
	channels, err := s.configClient.DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{})
	if err == nil && len(channels.DeliveryChannels) > 0 {
		status.DeliveryChannel = aws.ToString(channels.DeliveryChannels[0].S3BucketName)
	}

	if status.IsEnabled {
		status.Severity = SeverityLow
		status.Description = "AWS Config is enabled and recording"
		status.Recommendation = "Continue monitoring Config compliance"
	} else {
		status.Severity = SeverityCritical
		status.Description = "AWS Config recorder is not actively recording"
		status.Recommendation = "Start the Config recorder to track resource changes"
	}

	return status, nil
}

// GetEBSEncryptionStatus checks if EBS default encryption is enabled
func (s *service) GetEBSEncryptionStatus(ctx context.Context) (*EBSEncryptionStatus, error) {
	status := &EBSEncryptionStatus{}

	encryption, err := s.ec2Client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		status.DefaultEncryptionEnabled = false
		status.Severity = SeverityHigh
		status.Description = "Unable to check EBS default encryption"
		status.Recommendation = "Enable EBS default encryption"
		return status, nil
	}

	status.DefaultEncryptionEnabled = aws.ToBool(encryption.EbsEncryptionByDefault)

	if status.DefaultEncryptionEnabled {
		// Get default KMS key
		key, _ := s.ec2Client.GetEbsDefaultKmsKeyId(ctx, &ec2.GetEbsDefaultKmsKeyIdInput{})
		if key != nil {
			status.DefaultKMSKeyID = aws.ToString(key.KmsKeyId)
		}

		status.Severity = SeverityLow
		status.Description = "EBS default encryption is enabled"
		status.Recommendation = "Continue using encryption for all EBS volumes"
	} else {
		status.Severity = SeverityHigh
		status.Description = "EBS default encryption is NOT enabled - new volumes may be unencrypted"
		status.Recommendation = "Enable EBS default encryption for the region"
	}

	return status, nil
}

// GetKMSKeyRotationStatus checks KMS key rotation
func (s *service) GetKMSKeyRotationStatus(ctx context.Context) ([]KMSKeyRotation, error) {
	var results []KMSKeyRotation

	paginator := kms.NewListKeysPaginator(s.kmsClient, &kms.ListKeysInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, key := range page.Keys {
			keyID := aws.ToString(key.KeyId)

			// Get key metadata
			keyInfo, err := s.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				continue
			}

			// Skip AWS managed keys
			if keyInfo.KeyMetadata.KeyManager == "AWS" {
				continue
			}

			// Check rotation status
			rotation, err := s.kmsClient.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				continue
			}

			rotationEnabled := rotation.KeyRotationEnabled

			severity := SeverityLow
			description := "Key rotation enabled"
			recommendation := "Continue with automatic key rotation"

			if !rotationEnabled {
				severity = SeverityMedium
				description = "Key rotation is NOT enabled"
				recommendation = "Enable automatic key rotation for compliance"
			}

			results = append(results, KMSKeyRotation{
				KeyID:           keyID,
				KeyARN:          aws.ToString(keyInfo.KeyMetadata.Arn),
				RotationEnabled: rotationEnabled,
				Severity:        severity,
				Description:     description,
				Recommendation:  recommendation,
			})
		}
	}

	return results, nil
}

// Helper function to check if any volumes are unencrypted
func (s *service) GetUnencryptedVolumes(ctx context.Context) (int, error) {
	count := 0

	paginator := ec2.NewDescribeVolumesPaginator(s.ec2Client, &ec2.DescribeVolumesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return 0, err
		}

		for _, vol := range page.Volumes {
			if vol.State == ec2types.VolumeStateAvailable || vol.State == ec2types.VolumeStateInUse {
				if !aws.ToBool(vol.Encrypted) {
					count++
				}
			}
		}
	}

	return count, nil
}
