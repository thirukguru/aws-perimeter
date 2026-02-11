// Package ekssecurity provides security analysis for Amazon EKS.
package ekssecurity

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"

	// Minimum supported K8s version
	MinK8sVersion = "1.28"
)

// EKSRisk represents a security risk in EKS configuration
type EKSRisk struct {
	ClusterName    string
	NodeGroupName  string
	RiskType       string
	Severity       string
	Description    string
	Recommendation string
}

// Service interface for EKS security analysis
type Service interface {
	GetEKSRisks(ctx context.Context) ([]EKSRisk, error)
}

type service struct {
	client *eks.Client
}

// NewService creates a new EKS security service
func NewService(cfg aws.Config) Service {
	return &service{
		client: eks.NewFromConfig(cfg),
	}
}

// GetEKSRisks analyzes EKS clusters for security issues
func (s *service) GetEKSRisks(ctx context.Context) ([]EKSRisk, error) {
	var risks []EKSRisk

	// List all clusters
	clustersPaginator := eks.NewListClustersPaginator(s.client, &eks.ListClustersInput{})

	for clustersPaginator.HasMorePages() {
		clustersPage, err := clustersPaginator.NextPage(ctx)
		if err != nil {
			// Return what we have on permission error
			return risks, nil
		}

		for _, clusterName := range clustersPage.Clusters {
			clusterRisks, _ := s.analyzeCluster(ctx, clusterName)
			risks = append(risks, clusterRisks...)
		}
	}

	return risks, nil
}

// analyzeCluster performs security analysis on a single EKS cluster
func (s *service) analyzeCluster(ctx context.Context, clusterName string) ([]EKSRisk, error) {
	var risks []EKSRisk

	// Describe cluster
	cluster, err := s.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return risks, err
	}

	if cluster.Cluster == nil {
		return risks, nil
	}

	c := cluster.Cluster

	// 1. Check public endpoint access
	if c.ResourcesVpcConfig != nil {
		if c.ResourcesVpcConfig.EndpointPublicAccess {
			severity := SeverityHigh
			description := "Cluster API endpoint is publicly accessible"

			// Check if public access CIDRs are restricted
			if len(c.ResourcesVpcConfig.PublicAccessCidrs) > 0 {
				hasOpenCIDR := false
				for _, cidr := range c.ResourcesVpcConfig.PublicAccessCidrs {
					if cidr == "0.0.0.0/0" {
						hasOpenCIDR = true
						break
					}
				}
				if hasOpenCIDR {
					severity = SeverityCritical
					description = "Cluster API endpoint is publicly accessible from any IP (0.0.0.0/0)"
				} else {
					severity = SeverityMedium
					description = "Cluster API endpoint is publicly accessible with restricted CIDRs"
				}
			}

			risks = append(risks, EKSRisk{
				ClusterName:    clusterName,
				RiskType:       "PublicEndpoint",
				Severity:       severity,
				Description:    description,
				Recommendation: "Disable public endpoint access or restrict to specific CIDRs",
			})
		}

		if !c.ResourcesVpcConfig.EndpointPrivateAccess {
			risks = append(risks, EKSRisk{
				ClusterName:    clusterName,
				RiskType:       "NoPrivateEndpoint",
				Severity:       SeverityMedium,
				Description:    "Cluster has no private endpoint access",
				Recommendation: "Enable private endpoint access for internal cluster communication",
			})
		}
	}

	// 2. Check control plane logging
	if c.Logging != nil && c.Logging.ClusterLogging != nil {
		allLogsEnabled := true
		enabledLogs := []string{}

		for _, logSetup := range c.Logging.ClusterLogging {
			if logSetup.Enabled != nil && *logSetup.Enabled {
				for _, logType := range logSetup.Types {
					enabledLogs = append(enabledLogs, string(logType))
				}
			}
		}

		requiredLogs := []types.LogType{
			types.LogTypeApi,
			types.LogTypeAudit,
			types.LogTypeAuthenticator,
		}

		for _, req := range requiredLogs {
			found := false
			for _, enabled := range enabledLogs {
				if enabled == string(req) {
					found = true
					break
				}
			}
			if !found {
				allLogsEnabled = false
				break
			}
		}

		if !allLogsEnabled {
			risks = append(risks, EKSRisk{
				ClusterName:    clusterName,
				RiskType:       "IncompleteLogging",
				Severity:       SeverityHigh,
				Description:    "Not all control plane logs are enabled (api, audit, authenticator required)",
				Recommendation: "Enable all control plane log types for security monitoring",
			})
		}
	} else {
		risks = append(risks, EKSRisk{
			ClusterName:    clusterName,
			RiskType:       "NoControlPlaneLogging",
			Severity:       SeverityCritical,
			Description:    "Control plane logging is not configured",
			Recommendation: "Enable audit, api, and authenticator logs to CloudWatch",
		})
	}

	// 3. Check secrets encryption
	secretsEncrypted := false
	if c.EncryptionConfig != nil {
		for _, config := range c.EncryptionConfig {
			for _, resource := range config.Resources {
				if resource == "secrets" {
					secretsEncrypted = true
					break
				}
			}
		}
	}

	if !secretsEncrypted {
		risks = append(risks, EKSRisk{
			ClusterName:    clusterName,
			RiskType:       "SecretsNotEncrypted",
			Severity:       SeverityHigh,
			Description:    "Kubernetes secrets are not encrypted with KMS",
			Recommendation: "Enable envelope encryption for secrets using a KMS key",
		})
	}

	// 4. Check Kubernetes version
	if c.Version != nil {
		version := aws.ToString(c.Version)
		if isOutdatedVersion(version) {
			risks = append(risks, EKSRisk{
				ClusterName:    clusterName,
				RiskType:       "OutdatedK8sVersion",
				Severity:       SeverityMedium,
				Description:    "Cluster is running outdated Kubernetes version: " + version,
				Recommendation: "Upgrade to Kubernetes " + MinK8sVersion + " or later",
			})
		}
	}

	// 5. Check OIDC provider
	if c.Identity == nil || c.Identity.Oidc == nil || c.Identity.Oidc.Issuer == nil {
		risks = append(risks, EKSRisk{
			ClusterName:    clusterName,
			RiskType:       "NoOIDCProvider",
			Severity:       SeverityMedium,
			Description:    "OIDC provider not configured for IAM roles for service accounts",
			Recommendation: "Create OIDC provider to enable IRSA for pod-level IAM",
		})
	}

	// 6. Check cluster age (very old clusters may have security debt)
	if c.CreatedAt != nil {
		age := time.Since(*c.CreatedAt)
		if age.Hours() > 24*365*2 { // 2 years
			risks = append(risks, EKSRisk{
				ClusterName:    clusterName,
				RiskType:       "LegacyCluster",
				Severity:       SeverityLow,
				Description:    "Cluster is over 2 years old - may have accumulated security debt",
				Recommendation: "Review cluster configuration against current best practices",
			})
		}
	}

	// 7. Check access configuration mode
	if c.AccessConfig != nil {
		if c.AccessConfig.AuthenticationMode == types.AuthenticationModeConfigMap {
			risks = append(risks, EKSRisk{
				ClusterName:    clusterName,
				RiskType:       "LegacyAuthMode",
				Severity:       SeverityMedium,
				Description:    "Cluster uses legacy aws-auth ConfigMap for authentication",
				Recommendation: "Migrate to EKS access entries for better access management",
			})
		}
	}

	// Analyze node groups
	nodeGroupRisks, _ := s.analyzeNodeGroups(ctx, clusterName)
	risks = append(risks, nodeGroupRisks...)

	return risks, nil
}

// analyzeNodeGroups checks node group configurations
func (s *service) analyzeNodeGroups(ctx context.Context, clusterName string) ([]EKSRisk, error) {
	var risks []EKSRisk

	nodeGroupsPaginator := eks.NewListNodegroupsPaginator(s.client, &eks.ListNodegroupsInput{
		ClusterName: aws.String(clusterName),
	})

	for nodeGroupsPaginator.HasMorePages() {
		nodeGroupsPage, err := nodeGroupsPaginator.NextPage(ctx)
		if err != nil {
			return risks, nil
		}

		for _, ngName := range nodeGroupsPage.Nodegroups {
			ng, err := s.client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   aws.String(clusterName),
				NodegroupName: aws.String(ngName),
			})
			if err != nil {
				continue
			}

			if ng.Nodegroup == nil {
				continue
			}

			nodeGroup := ng.Nodegroup

			// Check if node group is in public subnets
			if nodeGroup.Subnets != nil {
				// If node group has public subnets, it might be exposed
				// This is a heuristic - ideally we'd check if subnets are public
				for _, subnet := range nodeGroup.Subnets {
					if strings.Contains(strings.ToLower(subnet), "public") {
						risks = append(risks, EKSRisk{
							ClusterName:    clusterName,
							NodeGroupName:  ngName,
							RiskType:       "PublicSubnetNodes",
							Severity:       SeverityMedium,
							Description:    "Node group may be using public subnets",
							Recommendation: "Place worker nodes in private subnets",
						})
						break
					}
				}
			}

			// Check remote access configuration
			if nodeGroup.RemoteAccess != nil {
				if nodeGroup.RemoteAccess.Ec2SshKey != nil {
					// SSH key is configured
					if nodeGroup.RemoteAccess.SourceSecurityGroups == nil ||
						len(nodeGroup.RemoteAccess.SourceSecurityGroups) == 0 {
						risks = append(risks, EKSRisk{
							ClusterName:    clusterName,
							NodeGroupName:  ngName,
							RiskType:       "UnrestrictedSSH",
							Severity:       SeverityHigh,
							Description:    "SSH access to nodes has no security group restrictions",
							Recommendation: "Restrict SSH access to specific security groups or remove SSH key",
						})
					}
				}
			}

			// Check node IAM role
			if nodeGroup.NodeRole != nil {
				role := aws.ToString(nodeGroup.NodeRole)
				if strings.Contains(strings.ToLower(role), "admin") {
					risks = append(risks, EKSRisk{
						ClusterName:    clusterName,
						NodeGroupName:  ngName,
						RiskType:       "AdminNodeRole",
						Severity:       SeverityHigh,
						Description:    "Node group uses admin-level IAM role",
						Recommendation: "Use least-privilege IAM role for node group",
					})
				}
			}

			// Check AMI type for Bottlerocket (more secure)
			if nodeGroup.AmiType == types.AMITypesAl2X8664 || nodeGroup.AmiType == types.AMITypesAl2Arm64 {
				risks = append(risks, EKSRisk{
					ClusterName:    clusterName,
					NodeGroupName:  ngName,
					RiskType:       "StandardAMI",
					Severity:       SeverityLow,
					Description:    "Node group uses standard Amazon Linux AMI instead of Bottlerocket",
					Recommendation: "Consider Bottlerocket AMI for improved security posture",
				})
			}
		}
	}

	return risks, nil
}

// isOutdatedVersion checks if a K8s version is below minimum
func isOutdatedVersion(version string) bool {
	// Simple comparison - in production would use semver
	outdatedVersions := []string{"1.23", "1.24", "1.25", "1.26", "1.27"}
	for _, old := range outdatedVersions {
		if strings.HasPrefix(version, old) {
			return true
		}
	}
	return false
}
