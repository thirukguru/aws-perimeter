// Package ec2security provides EC2-specific security checks including EBS and AMI analysis.
package ec2security

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// EBSSnapshotRisk represents a publicly shared EBS snapshot
type EBSSnapshotRisk struct {
	SnapshotID     string
	VolumeID       string
	VolumeSize     int32
	IsPublic       bool
	SharedWith     []string // Account IDs the snapshot is shared with
	Encrypted      bool
	Description    string
	Severity       string
	RiskType       string
	Recommendation string
}

// PublicAMIRisk represents a publicly shared AMI
type PublicAMIRisk struct {
	ImageID        string
	ImageName      string
	IsPublic       bool
	CreationDate   string
	Description    string
	Severity       string
	Recommendation string
}

// Service is the interface for EC2 security analysis
type Service interface {
	GetPublicEBSSnapshots(ctx context.Context) ([]EBSSnapshotRisk, error)
	GetPublicAMIs(ctx context.Context, accountID string) ([]PublicAMIRisk, error)
}

type service struct {
	client *ec2.Client
}

// NewService creates a new EC2 security service
func NewService(cfg aws.Config) Service {
	return &service{
		client: ec2.NewFromConfig(cfg),
	}
}

// GetPublicEBSSnapshots finds EBS snapshots that are publicly accessible
// CIS AWS 2.2.2: Ensure EBS snapshots are not publicly restorable
func (s *service) GetPublicEBSSnapshots(ctx context.Context) ([]EBSSnapshotRisk, error) {
	var risks []EBSSnapshotRisk

	// Get all snapshots owned by this account
	paginator := ec2.NewDescribeSnapshotsPaginator(s.client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, snapshot := range output.Snapshots {
			// Check snapshot permissions
			permsOutput, err := s.client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
				SnapshotId: snapshot.SnapshotId,
				Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
			})
			if err != nil {
				continue // Skip if we can't get permissions
			}

			isPublic := false
			var sharedWith []string

			for _, perm := range permsOutput.CreateVolumePermissions {
				if perm.Group == types.PermissionGroupAll {
					isPublic = true
				}
				if perm.UserId != nil {
					sharedWith = append(sharedWith, *perm.UserId)
				}
			}

			if isPublic {
				risks = append(risks, EBSSnapshotRisk{
					SnapshotID:     aws.ToString(snapshot.SnapshotId),
					VolumeID:       aws.ToString(snapshot.VolumeId),
					VolumeSize:     aws.ToInt32(snapshot.VolumeSize),
					IsPublic:       true,
					Encrypted:      aws.ToBool(snapshot.Encrypted),
					Description:    aws.ToString(snapshot.Description),
					Severity:       SeverityCritical,
					RiskType:       "PUBLIC_SNAPSHOT",
					Recommendation: "Remove public access from this EBS snapshot. Use ec2 modify-snapshot-attribute --snapshot-id " + aws.ToString(snapshot.SnapshotId) + " --attribute createVolumePermission --operation-type remove --group-names all",
				})
			} else if len(sharedWith) > 0 {
				// Shared with specific accounts - could be risky
				risks = append(risks, EBSSnapshotRisk{
					SnapshotID:     aws.ToString(snapshot.SnapshotId),
					VolumeID:       aws.ToString(snapshot.VolumeId),
					VolumeSize:     aws.ToInt32(snapshot.VolumeSize),
					IsPublic:       false,
					SharedWith:     sharedWith,
					Encrypted:      aws.ToBool(snapshot.Encrypted),
					Description:    aws.ToString(snapshot.Description),
					Severity:       SeverityMedium,
					RiskType:       "SHARED_SNAPSHOT",
					Recommendation: "Review cross-account sharing for snapshot " + aws.ToString(snapshot.SnapshotId) + ". Ensure all shared accounts are trusted.",
				})
			}
		}
	}

	return risks, nil
}

// GetPublicAMIs finds AMIs owned by this account that are publicly accessible
// CIS: Ensure AMIs are not publicly accessible
func (s *service) GetPublicAMIs(ctx context.Context, accountID string) ([]PublicAMIRisk, error) {
	var risks []PublicAMIRisk

	// Get AMIs owned by this account
	output, err := s.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return nil, err
	}

	for _, image := range output.Images {
		if aws.ToBool(image.Public) {
			imageName := aws.ToString(image.Name)
			if imageName == "" {
				imageName = aws.ToString(image.ImageId)
			}

			risks = append(risks, PublicAMIRisk{
				ImageID:        aws.ToString(image.ImageId),
				ImageName:      imageName,
				IsPublic:       true,
				CreationDate:   aws.ToString(image.CreationDate),
				Description:    aws.ToString(image.Description),
				Severity:       SeverityCritical,
				Recommendation: "Make this AMI private. Use: aws ec2 modify-image-attribute --image-id " + aws.ToString(image.ImageId) + " --launch-permission \"Remove=[{Group=all}]\"",
			})
		}
	}

	return risks, nil
}
