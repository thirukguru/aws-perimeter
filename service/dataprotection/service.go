// Package dataprotection provides RDS, DynamoDB, Secrets, and backup security analysis.
package dataprotection

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// RDSSecurityRisk represents RDS security issues
type RDSSecurityRisk struct {
	DBInstanceID    string
	Engine          string
	IsPublic        bool
	IsEncrypted     bool
	MultiAZ         bool
	BackupRetention int32
	Severity        string
	Description     string
	Recommendation  string
}

// DynamoDBRisk represents DynamoDB security issues
type DynamoDBRisk struct {
	TableName           string
	IsEncrypted         bool
	PointInTimeRecovery bool
	DeletionProtection  bool
	Severity            string
	Description         string
	Recommendation      string
}

// SecretRotationRisk represents Secrets Manager rotation issues
type SecretRotationRisk struct {
	SecretARN       string
	SecretName      string
	RotationEnabled bool
	LastRotatedDays int
	Severity        string
	Description     string
	Recommendation  string
}

// BackupStatus represents AWS Backup status
type BackupStatus struct {
	VaultsCount        int
	ActivePlans        int
	ProtectedResources int
	Severity           string
	Description        string
	Recommendation     string
}

// BackupRisk represents AWS Backup security risks.
type BackupRisk struct {
	RiskType       string
	Severity       string
	Resource       string
	Description    string
	Recommendation string
}

type service struct {
	rdsClient     *rds.Client
	dynamoClient  *dynamodb.Client
	secretsClient *secretsmanager.Client
	backupClient  *backup.Client
	region        string
}

// Service is the interface for data protection security analysis
type Service interface {
	GetRDSSecurityRisks(ctx context.Context) ([]RDSSecurityRisk, error)
	GetDynamoDBRisks(ctx context.Context) ([]DynamoDBRisk, error)
	GetSecretRotationRisks(ctx context.Context) ([]SecretRotationRisk, error)
	GetBackupStatus(ctx context.Context) (*BackupStatus, error)
	GetBackupRisks(ctx context.Context) ([]BackupRisk, error)
}

// NewService creates a new data protection service
func NewService(cfg aws.Config) Service {
	return &service{
		rdsClient:     rds.NewFromConfig(cfg),
		dynamoClient:  dynamodb.NewFromConfig(cfg),
		secretsClient: secretsmanager.NewFromConfig(cfg),
		backupClient:  backup.NewFromConfig(cfg),
		region:        cfg.Region,
	}
}

// GetRDSSecurityRisks checks RDS instances for security issues
func (s *service) GetRDSSecurityRisks(ctx context.Context) ([]RDSSecurityRisk, error) {
	var risks []RDSSecurityRisk

	paginator := rds.NewDescribeDBInstancesPaginator(s.rdsClient, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, db := range page.DBInstances {
			var issues []string
			severity := SeverityLow

			isPublic := db.PubliclyAccessible != nil && *db.PubliclyAccessible
			isEncrypted := db.StorageEncrypted != nil && *db.StorageEncrypted
			multiAZ := db.MultiAZ != nil && *db.MultiAZ
			backupRetention := int32(0)
			if db.BackupRetentionPeriod != nil {
				backupRetention = *db.BackupRetentionPeriod
			}

			if isPublic {
				issues = append(issues, "publicly accessible")
				severity = SeverityCritical
			}
			if !isEncrypted {
				issues = append(issues, "not encrypted")
				if severity == SeverityLow {
					severity = SeverityHigh
				}
			}
			if backupRetention == 0 {
				issues = append(issues, "no backups")
				if severity == SeverityLow {
					severity = SeverityMedium
				}
			}

			if len(issues) > 0 {
				risks = append(risks, RDSSecurityRisk{
					DBInstanceID:    aws.ToString(db.DBInstanceIdentifier),
					Engine:          aws.ToString(db.Engine),
					IsPublic:        isPublic,
					IsEncrypted:     isEncrypted,
					MultiAZ:         multiAZ,
					BackupRetention: backupRetention,
					Severity:        severity,
					Description:     "RDS instance has security issues: " + joinIssues(issues),
					Recommendation:  "Disable public access, enable encryption, configure backups",
				})
			}
		}
	}

	return risks, nil
}

// GetDynamoDBRisks checks DynamoDB tables for security issues
func (s *service) GetDynamoDBRisks(ctx context.Context) ([]DynamoDBRisk, error) {
	var risks []DynamoDBRisk

	tables, err := s.dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		return nil, err
	}

	for _, tableName := range tables.TableNames {
		table, err := s.dynamoClient.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String(tableName),
		})
		if err != nil {
			continue
		}

		// Check point-in-time recovery
		pitr, _ := s.dynamoClient.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
			TableName: aws.String(tableName),
		})

		pitrEnabled := false
		if pitr != nil && pitr.ContinuousBackupsDescription != nil &&
			pitr.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
			pitrEnabled = pitr.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == "ENABLED"
		}

		deletionProtection := table.Table.DeletionProtectionEnabled != nil && *table.Table.DeletionProtectionEnabled

		var issues []string
		severity := SeverityLow

		if !pitrEnabled {
			issues = append(issues, "PITR disabled")
			severity = SeverityMedium
		}
		if !deletionProtection {
			issues = append(issues, "deletion protection disabled")
			if severity == SeverityLow {
				severity = SeverityMedium
			}
		}

		if len(issues) > 0 {
			risks = append(risks, DynamoDBRisk{
				TableName:           tableName,
				PointInTimeRecovery: pitrEnabled,
				DeletionProtection:  deletionProtection,
				Severity:            severity,
				Description:         "DynamoDB table: " + joinIssues(issues),
				Recommendation:      "Enable PITR and deletion protection",
			})
		}
	}

	return risks, nil
}

// GetSecretRotationRisks checks Secrets Manager for rotation issues
func (s *service) GetSecretRotationRisks(ctx context.Context) ([]SecretRotationRisk, error) {
	var risks []SecretRotationRisk

	paginator := secretsmanager.NewListSecretsPaginator(s.secretsClient, &secretsmanager.ListSecretsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, secret := range page.SecretList {
			rotationEnabled := secret.RotationEnabled != nil && *secret.RotationEnabled

			lastRotatedDays := -1
			if secret.LastRotatedDate != nil {
				lastRotatedDays = int(time.Since(*secret.LastRotatedDate).Hours() / 24)
			}

			severity := SeverityLow
			description := "Secret rotation enabled"

			if !rotationEnabled {
				severity = SeverityMedium
				description = "Secret rotation is NOT enabled"
			} else if lastRotatedDays > 90 {
				severity = SeverityMedium
				description = "Secret not rotated in 90+ days"
			}

			if severity != SeverityLow {
				risks = append(risks, SecretRotationRisk{
					SecretARN:       aws.ToString(secret.ARN),
					SecretName:      aws.ToString(secret.Name),
					RotationEnabled: rotationEnabled,
					LastRotatedDays: lastRotatedDays,
					Severity:        severity,
					Description:     description,
					Recommendation:  "Enable automatic secret rotation",
				})
			}
		}
	}

	return risks, nil
}

// GetBackupStatus checks AWS Backup configuration
func (s *service) GetBackupStatus(ctx context.Context) (*BackupStatus, error) {
	status := &BackupStatus{}

	// Count backup vaults
	vaults, err := s.backupClient.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
	if err == nil {
		status.VaultsCount = len(vaults.BackupVaultList)
	}

	// Count backup plans
	plans, err := s.backupClient.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})
	if err == nil {
		status.ActivePlans = len(plans.BackupPlansList)
	}

	// Count protected resources
	resources, err := s.backupClient.ListProtectedResources(ctx, &backup.ListProtectedResourcesInput{})
	if err == nil {
		status.ProtectedResources = len(resources.Results)
	}

	if status.VaultsCount == 0 || status.ActivePlans == 0 {
		status.Severity = SeverityHigh
		status.Description = "AWS Backup not configured"
		status.Recommendation = "Configure AWS Backup with backup plans for critical resources"
	} else if status.ProtectedResources == 0 {
		status.Severity = SeverityMedium
		status.Description = "No resources protected by AWS Backup"
		status.Recommendation = "Add critical resources to backup plans"
	} else {
		status.Severity = SeverityLow
		status.Description = "AWS Backup is configured"
		status.Recommendation = "Continue monitoring backup compliance"
	}

	return status, nil
}

// GetBackupRisks evaluates Backup & DR misconfiguration risks.
func (s *service) GetBackupRisks(ctx context.Context) ([]BackupRisk, error) {
	var risks []BackupRisk

	vaultsOut, vaultErr := s.backupClient.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
	plansOut, plansErr := s.backupClient.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})
	protectedOut, protectedErr := s.backupClient.ListProtectedResources(ctx, &backup.ListProtectedResourcesInput{})

	if plansErr == nil && len(plansOut.BackupPlansList) == 0 {
		risks = append(risks, BackupRisk{
			RiskType:       "NoAWSBackupPlan",
			Severity:       SeverityHigh,
			Resource:       "AWS Backup",
			Description:    "No AWS Backup plans are configured",
			Recommendation: "Create AWS Backup plans for critical resources",
		})
	}

	if vaultErr == nil {
		for _, v := range vaultsOut.BackupVaultList {
			kmsArn := strings.TrimSpace(aws.ToString(v.EncryptionKeyArn))
			if kmsArn == "" {
				risks = append(risks, BackupRisk{
					RiskType:       "BackupVaultUnencrypted",
					Severity:       SeverityMedium,
					Resource:       aws.ToString(v.BackupVaultName),
					Description:    "Backup vault has no KMS key configured",
					Recommendation: "Configure backup vault encryption with a KMS key",
				})
			}
		}
	}

	crossRegionEnabled := false
	minRetentionDays := int64(-1)
	if plansErr == nil {
		for _, planRef := range plansOut.BackupPlansList {
			planID := aws.ToString(planRef.BackupPlanId)
			if strings.TrimSpace(planID) == "" {
				continue
			}
			plan, err := s.backupClient.GetBackupPlan(ctx, &backup.GetBackupPlanInput{
				BackupPlanId: aws.String(planID),
			})
			if err != nil || plan.BackupPlan == nil {
				continue
			}
			for _, rule := range plan.BackupPlan.Rules {
				if rule.Lifecycle != nil && rule.Lifecycle.DeleteAfterDays != nil {
					days := *rule.Lifecycle.DeleteAfterDays
					if minRetentionDays == -1 || days < minRetentionDays {
						minRetentionDays = days
					}
				}
				for _, copyAction := range rule.CopyActions {
					if isCrossRegionVaultArn(aws.ToString(copyAction.DestinationBackupVaultArn), s.region) {
						crossRegionEnabled = true
					}
				}
			}
		}
	}

	if plansErr == nil && len(plansOut.BackupPlansList) > 0 && !crossRegionEnabled {
		risks = append(risks, BackupRisk{
			RiskType:       "NoCrossRegionBackup",
			Severity:       SeverityMedium,
			Resource:       "AWS Backup Plans",
			Description:    "No cross-region backup copy actions are configured",
			Recommendation: "Configure cross-region backup copy for disaster recovery",
		})
	}

	if minRetentionDays > -1 && minRetentionDays < 30 {
		risks = append(risks, BackupRisk{
			RiskType:       "ShortBackupRetention",
			Severity:       SeverityMedium,
			Resource:       "AWS Backup Plans",
			Description:    "Backup retention is configured for less than 30 days",
			Recommendation: "Set lifecycle retention to at least 30 days for critical data",
		})
	}

	if protectedErr == nil {
		protectedTypes := map[string]bool{}
		for _, pr := range protectedOut.Results {
			protectedTypes[strings.ToUpper(aws.ToString(pr.ResourceType))] = true
		}

		expected := []string{"EC2", "RDS", "EFS"}
		for _, typ := range expected {
			if !hasProtectedType(protectedTypes, typ) {
				risks = append(risks, BackupRisk{
					RiskType:       "CriticalResourceNotInBackupPlan",
					Severity:       SeverityMedium,
					Resource:       typ,
					Description:    "No protected " + typ + " resources found in AWS Backup",
					Recommendation: "Add critical " + typ + " resources to backup plans",
				})
			}
		}
	}

	return risks, nil
}

func hasProtectedType(types map[string]bool, want string) bool {
	want = strings.ToUpper(strings.TrimSpace(want))
	for k := range types {
		if k == want || strings.Contains(k, want) {
			return true
		}
	}
	return false
}

func isCrossRegionVaultArn(vaultArn, currentRegion string) bool {
	parts := strings.Split(vaultArn, ":")
	if len(parts) < 4 {
		return false
	}
	destRegion := strings.TrimSpace(parts[3])
	return destRegion != "" && currentRegion != "" && !strings.EqualFold(destRegion, currentRegion)
}

func joinIssues(issues []string) string {
	if len(issues) == 0 {
		return ""
	}
	result := issues[0]
	for i := 1; i < len(issues); i++ {
		result += ", " + issues[i]
	}
	return result
}
