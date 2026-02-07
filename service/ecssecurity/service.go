// Package ecssecurity provides security analysis for Amazon ECS.
package ecssecurity

import (
	"context"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// ECSRisk represents a security risk in ECS configuration
type ECSRisk struct {
	ClusterName    string
	ServiceName    string
	TaskDefArn     string
	ContainerName  string
	RiskType       string
	Severity       string
	Description    string
	Recommendation string
}

// Service interface for ECS security analysis
type Service interface {
	GetECSRisks(ctx context.Context) ([]ECSRisk, error)
}

type service struct {
	client *ecs.Client
}

// NewService creates a new ECS security service
func NewService(cfg aws.Config) Service {
	return &service{
		client: ecs.NewFromConfig(cfg),
	}
}

// Patterns for detecting secrets in environment variables
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^AWS_ACCESS_KEY_ID$`),
	regexp.MustCompile(`(?i)^AWS_SECRET_ACCESS_KEY$`),
	regexp.MustCompile(`(?i)^AWS_SESSION_TOKEN$`),
	regexp.MustCompile(`(?i).*PASSWORD.*`),
	regexp.MustCompile(`(?i).*SECRET.*`),
	regexp.MustCompile(`(?i).*API_KEY.*`),
	regexp.MustCompile(`(?i).*APIKEY.*`),
	regexp.MustCompile(`(?i).*TOKEN.*`),
	regexp.MustCompile(`(?i).*PRIVATE_KEY.*`),
	regexp.MustCompile(`(?i)^DB_.*`),
}

// GetECSRisks analyzes ECS clusters, services, and task definitions for security issues
func (s *service) GetECSRisks(ctx context.Context) ([]ECSRisk, error) {
	var risks []ECSRisk

	// List all clusters
	clustersPaginator := ecs.NewListClustersPaginator(s.client, &ecs.ListClustersInput{})

	for clustersPaginator.HasMorePages() {
		clustersPage, err := clustersPaginator.NextPage(ctx)
		if err != nil {
			// Return what we have on permission error
			return risks, nil
		}

		if len(clustersPage.ClusterArns) == 0 {
			continue
		}

		// Describe clusters
		descClusters, err := s.client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: clustersPage.ClusterArns,
			Include:  []types.ClusterField{types.ClusterFieldSettings},
		})
		if err != nil {
			continue
		}

		for _, cluster := range descClusters.Clusters {
			clusterName := aws.ToString(cluster.ClusterName)

			// Check cluster settings
			risks = append(risks, s.checkClusterSettings(cluster)...)

			// List task definitions used by services in this cluster
			servicesPaginator := ecs.NewListServicesPaginator(s.client, &ecs.ListServicesInput{
				Cluster: cluster.ClusterArn,
			})

			for servicesPaginator.HasMorePages() {
				servicesPage, err := servicesPaginator.NextPage(ctx)
				if err != nil {
					break
				}

				if len(servicesPage.ServiceArns) == 0 {
					continue
				}

				// Describe services
				descServices, err := s.client.DescribeServices(ctx, &ecs.DescribeServicesInput{
					Cluster:  cluster.ClusterArn,
					Services: servicesPage.ServiceArns,
				})
				if err != nil {
					continue
				}

				for _, svc := range descServices.Services {
					serviceName := aws.ToString(svc.ServiceName)
					taskDefArn := aws.ToString(svc.TaskDefinition)

					// Check service for public exposure
					risks = append(risks, s.checkServiceExposure(clusterName, serviceName, svc)...)

					// Check task definition
					taskDefRisks, _ := s.checkTaskDefinition(ctx, clusterName, serviceName, taskDefArn)
					risks = append(risks, taskDefRisks...)
				}
			}
		}
	}

	return risks, nil
}

// checkClusterSettings checks cluster-level security settings
func (s *service) checkClusterSettings(cluster types.Cluster) []ECSRisk {
	var risks []ECSRisk
	clusterName := aws.ToString(cluster.ClusterName)

	// Check if Container Insights is disabled
	containerInsightsEnabled := false
	for _, setting := range cluster.Settings {
		if setting.Name == types.ClusterSettingNameContainerInsights {
			if aws.ToString(setting.Value) == "enabled" {
				containerInsightsEnabled = true
			}
		}
	}

	if !containerInsightsEnabled {
		risks = append(risks, ECSRisk{
			ClusterName:    clusterName,
			RiskType:       "ContainerInsightsDisabled",
			Severity:       SeverityMedium,
			Description:    "Container Insights is not enabled for monitoring",
			Recommendation: "Enable Container Insights for observability and security monitoring",
		})
	}

	// Check execute command configuration
	if cluster.Configuration != nil && cluster.Configuration.ExecuteCommandConfiguration != nil {
		execConfig := cluster.Configuration.ExecuteCommandConfiguration
		if execConfig.Logging == types.ExecuteCommandLoggingNone {
			risks = append(risks, ECSRisk{
				ClusterName:    clusterName,
				RiskType:       "ECSExecNoLogging",
				Severity:       SeverityHigh,
				Description:    "ECS Exec is configured without logging - commands are not audited",
				Recommendation: "Enable logging for ECS Exec to CloudWatch or S3",
			})
		}
	}

	return risks
}

// checkServiceExposure checks if a service is publicly exposed
func (s *service) checkServiceExposure(clusterName, serviceName string, svc types.Service) []ECSRisk {
	var risks []ECSRisk

	// Check network configuration for public IP assignment
	if svc.NetworkConfiguration != nil && svc.NetworkConfiguration.AwsvpcConfiguration != nil {
		if svc.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp == types.AssignPublicIpEnabled {
			risks = append(risks, ECSRisk{
				ClusterName:    clusterName,
				ServiceName:    serviceName,
				RiskType:       "PublicIPAssigned",
				Severity:       SeverityHigh,
				Description:    "Service has public IP assignment enabled - containers accessible from internet",
				Recommendation: "Use private subnets with NAT Gateway or VPC endpoints instead",
			})
		}
	}

	// Check if ECS Exec is enabled on service
	if svc.EnableExecuteCommand {
		risks = append(risks, ECSRisk{
			ClusterName:    clusterName,
			ServiceName:    serviceName,
			RiskType:       "ECSExecEnabled",
			Severity:       SeverityMedium,
			Description:    "ECS Exec is enabled - allows shell access to running containers",
			Recommendation: "Disable ECS Exec if not needed, ensure proper IAM controls if required",
		})
	}

	return risks
}

// checkTaskDefinition analyzes a task definition for security issues
func (s *service) checkTaskDefinition(ctx context.Context, clusterName, serviceName, taskDefArn string) ([]ECSRisk, error) {
	var risks []ECSRisk

	if taskDefArn == "" {
		return risks, nil
	}

	taskDef, err := s.client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(taskDefArn),
	})
	if err != nil {
		return risks, err
	}

	if taskDef.TaskDefinition == nil {
		return risks, nil
	}

	td := taskDef.TaskDefinition
	taskDefFamily := aws.ToString(td.Family)

	// Check network mode
	if td.NetworkMode == types.NetworkModeHost {
		risks = append(risks, ECSRisk{
			ClusterName:    clusterName,
			ServiceName:    serviceName,
			TaskDefArn:     taskDefArn,
			RiskType:       "HostNetworkMode",
			Severity:       SeverityHigh,
			Description:    "Task uses host network mode - container has full network access to host",
			Recommendation: "Use awsvpc or bridge network mode for isolation",
		})
	}

	// Check each container definition
	for _, container := range td.ContainerDefinitions {
		containerName := aws.ToString(container.Name)

		// Check privileged mode
		if container.Privileged != nil && *container.Privileged {
			risks = append(risks, ECSRisk{
				ClusterName:    clusterName,
				ServiceName:    serviceName,
				TaskDefArn:     taskDefArn,
				ContainerName:  containerName,
				RiskType:       "PrivilegedContainer",
				Severity:       SeverityCritical,
				Description:    "Container runs in privileged mode - has root access to host",
				Recommendation: "Remove privileged flag unless absolutely required",
			})
		}

		// Check if running as root
		if container.User == nil || aws.ToString(container.User) == "" || aws.ToString(container.User) == "root" || aws.ToString(container.User) == "0" {
			risks = append(risks, ECSRisk{
				ClusterName:    clusterName,
				ServiceName:    serviceName,
				TaskDefArn:     taskDefArn,
				ContainerName:  containerName,
				RiskType:       "RunAsRoot",
				Severity:       SeverityMedium,
				Description:    "Container runs as root user",
				Recommendation: "Specify a non-root user in the container definition",
			})
		}

		// Check for secrets in environment variables
		for _, env := range container.Environment {
			envName := aws.ToString(env.Name)
			envValue := aws.ToString(env.Value)

			for _, pattern := range secretPatterns {
				if pattern.MatchString(envName) && envValue != "" {
					risks = append(risks, ECSRisk{
						ClusterName:    clusterName,
						ServiceName:    serviceName,
						TaskDefArn:     taskDefArn,
						ContainerName:  containerName,
						RiskType:       "HardcodedSecret",
						Severity:       SeverityCritical,
						Description:    "Hardcoded secret in environment variable: " + envName,
						Recommendation: "Use AWS Secrets Manager or SSM Parameter Store instead",
					})
					break
				}
			}
		}

		// Check image source - should be from ECR
		image := aws.ToString(container.Image)
		if !strings.Contains(image, ".dkr.ecr.") && !strings.Contains(image, "amazonaws.com") {
			// Check if it's a public image
			if strings.Contains(image, "docker.io") || strings.Contains(image, "gcr.io") ||
				strings.Contains(image, "quay.io") || !strings.Contains(image, "/") ||
				strings.HasPrefix(image, "public.ecr.aws") {
				risks = append(risks, ECSRisk{
					ClusterName:    clusterName,
					ServiceName:    serviceName,
					TaskDefArn:     taskDefArn,
					ContainerName:  containerName,
					RiskType:       "PublicImage",
					Severity:       SeverityMedium,
					Description:    "Container uses public image: " + taskDefFamily + " (" + image + ")",
					Recommendation: "Pull images from private ECR repository for supply chain security",
				})
			}
		}

		// Check for read-only root filesystem
		if container.ReadonlyRootFilesystem == nil || !*container.ReadonlyRootFilesystem {
			risks = append(risks, ECSRisk{
				ClusterName:    clusterName,
				ServiceName:    serviceName,
				TaskDefArn:     taskDefArn,
				ContainerName:  containerName,
				RiskType:       "WritableRootFS",
				Severity:       SeverityLow,
				Description:    "Container has writable root filesystem",
				Recommendation: "Enable readonlyRootFilesystem for better security",
			})
		}

		// Check Linux capabilities
		if container.LinuxParameters != nil && container.LinuxParameters.Capabilities != nil {
			caps := container.LinuxParameters.Capabilities
			for _, addCap := range caps.Add {
				if addCap == "SYS_ADMIN" || addCap == "NET_ADMIN" || addCap == "ALL" {
					risks = append(risks, ECSRisk{
						ClusterName:    clusterName,
						ServiceName:    serviceName,
						TaskDefArn:     taskDefArn,
						ContainerName:  containerName,
						RiskType:       "DangerousCapability",
						Severity:       SeverityHigh,
						Description:    "Container has dangerous Linux capability: " + string(addCap),
						Recommendation: "Remove unnecessary Linux capabilities",
					})
				}
			}
		}
	}

	// Check task role - look for overly permissive
	if td.TaskRoleArn != nil {
		taskRole := aws.ToString(td.TaskRoleArn)
		if strings.Contains(strings.ToLower(taskRole), "admin") {
			risks = append(risks, ECSRisk{
				ClusterName:    clusterName,
				ServiceName:    serviceName,
				TaskDefArn:     taskDefArn,
				RiskType:       "AdminTaskRole",
				Severity:       SeverityHigh,
				Description:    "Task uses admin-level IAM role",
				Recommendation: "Apply least-privilege principle to task IAM role",
			})
		}
	}

	return risks, nil
}
