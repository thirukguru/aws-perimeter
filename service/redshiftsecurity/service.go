// Package redshiftsecurity provides Redshift security analysis.
package redshiftsecurity

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// RedshiftRisk represents a Redshift security misconfiguration.
type RedshiftRisk struct {
	RiskType       string
	Severity       string
	Resource       string
	Description    string
	Recommendation string
}

type service struct {
	redshiftClient *redshift.Client
}

// Service is the interface for Redshift security checks.
type Service interface {
	GetRedshiftSecurityRisks(ctx context.Context) ([]RedshiftRisk, error)
}

// NewService creates a new Redshift security service.
func NewService(cfg aws.Config) Service {
	return &service{
		redshiftClient: redshift.NewFromConfig(cfg),
	}
}

// GetRedshiftSecurityRisks evaluates Redshift clusters for security gaps.
func (s *service) GetRedshiftSecurityRisks(ctx context.Context) ([]RedshiftRisk, error) {
	var risks []RedshiftRisk

	paginator := redshift.NewDescribeClustersPaginator(s.redshiftClient, &redshift.DescribeClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// Service unavailable or no permissions in this account/region.
			return risks, nil
		}

		for _, cluster := range page.Clusters {
			clusterID := aws.ToString(cluster.ClusterIdentifier)
			if strings.TrimSpace(clusterID) == "" {
				continue
			}

			if boolFalse(cluster.PubliclyAccessible) {
				// Not a risk.
			} else if boolTrue(cluster.PubliclyAccessible) {
				risks = append(risks, RedshiftRisk{
					RiskType:       "PubliclyAccessibleCluster",
					Severity:       SeverityHigh,
					Resource:       clusterID,
					Description:    "Redshift cluster is publicly accessible",
					Recommendation: "Disable public accessibility and access via private networking/Bastion/VPN",
				})
			}

			if boolFalse(cluster.Encrypted) {
				risks = append(risks, RedshiftRisk{
					RiskType:       "ClusterEncryptionDisabled",
					Severity:       SeverityHigh,
					Resource:       clusterID,
					Description:    "Redshift cluster encryption at rest is disabled",
					Recommendation: "Enable encryption at rest with KMS-managed keys",
				})
			}

			// API does not expose password strength directly; use unmanaged master credentials
			// as weak-password-policy proxy signal.
			if strings.TrimSpace(aws.ToString(cluster.MasterPasswordSecretArn)) == "" {
				risks = append(risks, RedshiftRisk{
					RiskType:       "WeakMasterPasswordPolicy",
					Severity:       SeverityMedium,
					Resource:       clusterID,
					Description:    "Cluster is not configured to use managed admin credentials secret",
					Recommendation: "Enable Redshift managed admin credentials (Secrets Manager) and enforce strong password rotation",
				})
			}

			if boolFalse(cluster.EnhancedVpcRouting) {
				risks = append(risks, RedshiftRisk{
					RiskType:       "EnhancedVPCRoutingDisabled",
					Severity:       SeverityMedium,
					Resource:       clusterID,
					Description:    "Enhanced VPC routing is disabled",
					Recommendation: "Enable enhanced VPC routing so COPY/UNLOAD traffic stays within controlled VPC paths",
				})
			}

			loggingStatus, err := s.redshiftClient.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{
				ClusterIdentifier: aws.String(clusterID),
			})
			if err == nil && boolFalse(loggingStatus.LoggingEnabled) {
				risks = append(risks, RedshiftRisk{
					RiskType:       "AuditLoggingDisabled",
					Severity:       SeverityMedium,
					Resource:       clusterID,
					Description:    "Audit logging is disabled for Redshift cluster",
					Recommendation: "Enable Redshift audit logging to S3 and monitor logs for anomalous access/query patterns",
				})
			}
		}
	}

	return dedupeRisks(risks), nil
}

func boolFalse(v *bool) bool { return v != nil && !aws.ToBool(v) }
func boolTrue(v *bool) bool  { return v != nil && aws.ToBool(v) }

func dedupeRisks(in []RedshiftRisk) []RedshiftRisk {
	seen := map[string]bool{}
	out := make([]RedshiftRisk, 0, len(in))
	for _, r := range in {
		key := fmt.Sprintf("%s|%s", r.RiskType, r.Resource)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

var (
	_ = redshifttypes.Cluster{}
)
