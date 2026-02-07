// Package aurorasecurity provides Amazon Aurora security analysis.
package aurorasecurity

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// AuroraRisk represents a security finding for an Aurora cluster
type AuroraRisk struct {
	ClusterID      string
	ClusterARN     string
	Engine         string
	EngineVersion  string
	RiskType       string
	Severity       string
	Description    string
	Recommendation string
}

// Service is the interface for Aurora security analysis
type Service interface {
	GetAuroraRisks(ctx context.Context) ([]AuroraRisk, error)
}

type service struct {
	client *rds.Client
}

// NewService creates a new Aurora security service
func NewService(cfg aws.Config) Service {
	return &service{
		client: rds.NewFromConfig(cfg),
	}
}

// GetAuroraRisks analyzes Aurora clusters for security issues
func (s *service) GetAuroraRisks(ctx context.Context) ([]AuroraRisk, error) {
	var risks []AuroraRisk

	// List all Aurora clusters
	paginator := rds.NewDescribeDBClustersPaginator(s.client, &rds.DescribeDBClustersInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, cluster := range output.DBClusters {
			// Only process Aurora clusters
			engine := aws.ToString(cluster.Engine)
			if engine != "aurora" && engine != "aurora-mysql" && engine != "aurora-postgresql" {
				continue
			}

			clusterID := aws.ToString(cluster.DBClusterIdentifier)
			clusterARN := aws.ToString(cluster.DBClusterArn)

			// Check 1: Encryption at rest
			if !aws.ToBool(cluster.StorageEncrypted) {
				risks = append(risks, AuroraRisk{
					ClusterID:      clusterID,
					ClusterARN:     clusterARN,
					Engine:         engine,
					EngineVersion:  aws.ToString(cluster.EngineVersion),
					RiskType:       "NO_ENCRYPTION",
					Severity:       SeverityCritical,
					Description:    "Aurora cluster does not have storage encryption enabled.",
					Recommendation: "Enable encryption at rest. Note: This requires creating a new encrypted cluster and migrating data.",
				})
			}

			// Check 2: Public accessibility
			if aws.ToBool(cluster.PubliclyAccessible) {
				risks = append(risks, AuroraRisk{
					ClusterID:      clusterID,
					ClusterARN:     clusterARN,
					Engine:         engine,
					EngineVersion:  aws.ToString(cluster.EngineVersion),
					RiskType:       "PUBLICLY_ACCESSIBLE",
					Severity:       SeverityCritical,
					Description:    "Aurora cluster is publicly accessible from the internet.",
					Recommendation: "Disable public accessibility and use VPC security groups to control access.",
				})
			}

			// Check 3: Backup retention
			if cluster.BackupRetentionPeriod != nil && *cluster.BackupRetentionPeriod < 7 {
				risks = append(risks, AuroraRisk{
					ClusterID:      clusterID,
					ClusterARN:     clusterARN,
					Engine:         engine,
					EngineVersion:  aws.ToString(cluster.EngineVersion),
					RiskType:       "LOW_BACKUP_RETENTION",
					Severity:       SeverityMedium,
					Description:    "Aurora cluster has backup retention less than 7 days.",
					Recommendation: "Increase backup retention period to at least 7 days for data protection.",
				})
			}

			// Check 4: Deletion protection
			if !aws.ToBool(cluster.DeletionProtection) {
				risks = append(risks, AuroraRisk{
					ClusterID:      clusterID,
					ClusterARN:     clusterARN,
					Engine:         engine,
					EngineVersion:  aws.ToString(cluster.EngineVersion),
					RiskType:       "NO_DELETION_PROTECTION",
					Severity:       SeverityMedium,
					Description:    "Aurora cluster does not have deletion protection enabled.",
					Recommendation: "Enable deletion protection to prevent accidental deletion.",
				})
			}

			// Check 5: IAM authentication
			if !aws.ToBool(cluster.IAMDatabaseAuthenticationEnabled) {
				risks = append(risks, AuroraRisk{
					ClusterID:      clusterID,
					ClusterARN:     clusterARN,
					Engine:         engine,
					EngineVersion:  aws.ToString(cluster.EngineVersion),
					RiskType:       "NO_IAM_AUTH",
					Severity:       SeverityLow,
					Description:    "Aurora cluster does not have IAM database authentication enabled.",
					Recommendation: "Enable IAM database authentication for improved access control.",
				})
			}

			// Check 6: Multi-AZ (not applicable for Aurora Serverless)
			if cluster.EngineMode == nil || *cluster.EngineMode != "serverless" {
				// Check if there are instances in multiple AZs
				instanceCount := 0
				azSet := make(map[string]bool)

				for _, member := range cluster.DBClusterMembers {
					instanceCount++
					// We'd need to describe instances to get AZ, so just check count
					_ = member
				}

				if instanceCount < 2 {
					risks = append(risks, AuroraRisk{
						ClusterID:      clusterID,
						ClusterARN:     clusterARN,
						Engine:         engine,
						EngineVersion:  aws.ToString(cluster.EngineVersion),
						RiskType:       "SINGLE_INSTANCE",
						Severity:       SeverityMedium,
						Description:    "Aurora cluster has only one instance, limiting high availability.",
						Recommendation: "Add a read replica in a different AZ for high availability.",
					})
				}
				_ = azSet
			}

			// Check 7: Auto minor version upgrade
			// Need to check individual instances
			for _, member := range cluster.DBClusterMembers {
				instanceID := aws.ToString(member.DBInstanceIdentifier)
				instanceOutput, err := s.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
					DBInstanceIdentifier: aws.String(instanceID),
				})
				if err != nil {
					continue
				}

				for _, instance := range instanceOutput.DBInstances {
					if !aws.ToBool(instance.AutoMinorVersionUpgrade) {
						risks = append(risks, AuroraRisk{
							ClusterID:      clusterID,
							ClusterARN:     clusterARN,
							Engine:         engine,
							EngineVersion:  aws.ToString(cluster.EngineVersion),
							RiskType:       "NO_AUTO_UPGRADE",
							Severity:       SeverityLow,
							Description:    "Aurora instance " + instanceID + " does not have auto minor version upgrade enabled.",
							Recommendation: "Enable auto minor version upgrade to receive security patches automatically.",
						})
						break // Only report once per cluster
					}
				}
			}

			// Check 8: Performance Insights
			for _, member := range cluster.DBClusterMembers {
				instanceID := aws.ToString(member.DBInstanceIdentifier)
				instanceOutput, err := s.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
					DBInstanceIdentifier: aws.String(instanceID),
				})
				if err != nil {
					continue
				}

				for _, instance := range instanceOutput.DBInstances {
					if !aws.ToBool(instance.PerformanceInsightsEnabled) {
						risks = append(risks, AuroraRisk{
							ClusterID:      clusterID,
							ClusterARN:     clusterARN,
							Engine:         engine,
							EngineVersion:  aws.ToString(cluster.EngineVersion),
							RiskType:       "NO_PERFORMANCE_INSIGHTS",
							Severity:       SeverityLow,
							Description:    "Aurora instance " + instanceID + " does not have Performance Insights enabled.",
							Recommendation: "Enable Performance Insights for better database monitoring and troubleshooting.",
						})
						break // Only report once per cluster
					}
				}
			}

			// Check 9: CloudWatch Logs export
			if len(cluster.EnabledCloudwatchLogsExports) == 0 {
				risks = append(risks, AuroraRisk{
					ClusterID:      clusterID,
					ClusterARN:     clusterARN,
					Engine:         engine,
					EngineVersion:  aws.ToString(cluster.EngineVersion),
					RiskType:       "NO_LOG_EXPORT",
					Severity:       SeverityMedium,
					Description:    "Aurora cluster does not export logs to CloudWatch Logs.",
					Recommendation: "Enable log exports (audit, error, general, slowquery) for security monitoring.",
				})
			}

			// Check 10: Copy tags to snapshot
			if !aws.ToBool(cluster.CopyTagsToSnapshot) {
				risks = append(risks, AuroraRisk{
					ClusterID:      clusterID,
					ClusterARN:     clusterARN,
					Engine:         engine,
					EngineVersion:  aws.ToString(cluster.EngineVersion),
					RiskType:       "NO_COPY_TAGS",
					Severity:       SeverityLow,
					Description:    "Aurora cluster does not copy tags to snapshots.",
					Recommendation: "Enable copy tags to snapshot for better resource tracking and compliance.",
				})
			}
		}
	}

	return risks, nil
}

// Helper to check if cluster is Aurora
func isAuroraEngine(engine string) bool {
	return engine == "aurora" || engine == "aurora-mysql" || engine == "aurora-postgresql"
}
