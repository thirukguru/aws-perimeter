// Package aidetection provides security analysis for AI-powered attacks.
package aidetection

import (
	"context"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// AIRisk represents a security risk related to AI attacks
type AIRisk struct {
	RiskType       string
	Severity       string
	Resource       string
	Description    string
	Recommendation string
}

// Service interface for AI attack detection
type Service interface {
	GetAIRisks(ctx context.Context) ([]AIRisk, error)
}

type service struct {
	ec2Client     *ec2.Client
	bedrockClient *bedrock.Client
	cwClient      *cloudwatch.Client
	region        string
}

// NewService creates a new AI detection service
func NewService(cfg aws.Config) Service {
	return &service{
		ec2Client:     ec2.NewFromConfig(cfg),
		bedrockClient: bedrock.NewFromConfig(cfg),
		cwClient:      cloudwatch.NewFromConfig(cfg),
		region:        cfg.Region,
	}
}

// GPU instance types used for crypto mining and LLM abuse
var gpuInstanceTypes = map[string]bool{
	"p2.xlarge":      true,
	"p2.8xlarge":     true,
	"p2.16xlarge":    true,
	"p3.2xlarge":     true,
	"p3.8xlarge":     true,
	"p3.16xlarge":    true,
	"p3dn.24xlarge":  true,
	"p4d.24xlarge":   true,
	"p4de.24xlarge":  true,
	"p5.48xlarge":    true,
	"g3.4xlarge":     true,
	"g3.8xlarge":     true,
	"g3.16xlarge":    true,
	"g4dn.xlarge":    true,
	"g4dn.2xlarge":   true,
	"g4dn.4xlarge":   true,
	"g4dn.8xlarge":   true,
	"g4dn.12xlarge":  true,
	"g4dn.16xlarge":  true,
	"g4dn.metal":     true,
	"g5.xlarge":      true,
	"g5.2xlarge":     true,
	"g5.4xlarge":     true,
	"g5.8xlarge":     true,
	"g5.12xlarge":    true,
	"g5.16xlarge":    true,
	"g5.24xlarge":    true,
	"g5.48xlarge":    true,
	"inf1.xlarge":    true,
	"inf1.2xlarge":   true,
	"inf1.6xlarge":   true,
	"inf1.24xlarge":  true,
	"inf2.xlarge":    true,
	"inf2.8xlarge":   true,
	"inf2.24xlarge":  true,
	"inf2.48xlarge":  true,
	"trn1.2xlarge":   true,
	"trn1.32xlarge":  true,
	"trn1n.32xlarge": true,
}

// AWS credential patterns
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),          // Access Key ID
	regexp.MustCompile(`ASIA[0-9A-Z]{16}`),          // Temporary Access Key
	regexp.MustCompile(`(?i)aws_secret_access_key`), // Secret key variable
	regexp.MustCompile(`(?i)aws_session_token`),     // Session token
}

// GetAIRisks analyzes for AI-powered attack indicators
func (s *service) GetAIRisks(ctx context.Context) ([]AIRisk, error) {
	var risks []AIRisk

	// 1. Check for GPU instances (LLMjacking/mining targets)
	gpuRisks, _ := s.checkGPUInstances(ctx)
	risks = append(risks, gpuRisks...)

	// 2. Check Bedrock configuration
	bedrockRisks, _ := s.checkBedrockConfig(ctx)
	risks = append(risks, bedrockRisks...)

	// 3. Check for rapid resource provisioning
	rapidProvRisks, _ := s.checkRapidProvisioning(ctx)
	risks = append(risks, rapidProvRisks...)

	return risks, nil
}

// checkGPUInstances looks for GPU instances that could be targets for LLMjacking
func (s *service) checkGPUInstances(ctx context.Context) ([]AIRisk, error) {
	var risks []AIRisk

	paginator := ec2.NewDescribeInstancesPaginator(s.ec2Client, &ec2.DescribeInstancesInput{
		Filters: []ec2Types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return risks, nil
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				instanceType := string(instance.InstanceType)
				instanceID := aws.ToString(instance.InstanceId)

				// Check if it's a GPU instance
				if gpuInstanceTypes[instanceType] {
					// Get instance name from tags
					var instanceName string
					for _, tag := range instance.Tags {
						if aws.ToString(tag.Key) == "Name" {
							instanceName = aws.ToString(tag.Value)
							break
						}
					}

					severity := SeverityMedium
					// Higher severity for more powerful GPU instances
					if strings.HasPrefix(instanceType, "p4") || strings.HasPrefix(instanceType, "p5") {
						severity = SeverityHigh
					}

					risks = append(risks, AIRisk{
						RiskType:       "GPUInstanceRunning",
						Severity:       severity,
						Resource:       instanceID + " (" + instanceName + ")",
						Description:    "GPU instance type " + instanceType + " running - potential LLMjacking or cryptomining target",
						Recommendation: "Verify legitimate use; monitor for unusual usage patterns and cost spikes",
					})

					// Check if instance has public IP
					if instance.PublicIpAddress != nil {
						risks = append(risks, AIRisk{
							RiskType:       "GPUInstancePublicIP",
							Severity:       SeverityHigh,
							Resource:       instanceID,
							Description:    "GPU instance has public IP " + aws.ToString(instance.PublicIpAddress) + " - easily discoverable target",
							Recommendation: "Remove public IP; use private subnets with VPN/bastion access",
						})
					}

					// Check IMDSv2
					if instance.MetadataOptions != nil {
						if instance.MetadataOptions.HttpTokens != ec2Types.HttpTokensStateRequired {
							risks = append(risks, AIRisk{
								RiskType:       "GPUInstanceIMDSv1",
								Severity:       SeverityCritical,
								Resource:       instanceID,
								Description:    "GPU instance uses IMDSv1 - credentials easily stolen",
								Recommendation: "Require IMDSv2 tokens to protect instance credentials",
							})
						}
					}
				}
			}
		}
	}

	return risks, nil
}

// checkBedrockConfig analyzes Bedrock for abuse potential
func (s *service) checkBedrockConfig(ctx context.Context) ([]AIRisk, error) {
	var risks []AIRisk

	// List provisioned model throughputs (indicates Bedrock usage)
	throughputs, err := s.bedrockClient.ListProvisionedModelThroughputs(ctx, &bedrock.ListProvisionedModelThroughputsInput{})
	if err != nil {
		// Bedrock might not be enabled or no permissions - not an error
		return risks, nil
	}

	if throughputs.ProvisionedModelSummaries != nil {
		for _, pmt := range throughputs.ProvisionedModelSummaries {
			pmtName := aws.ToString(pmt.ProvisionedModelName)
			pmtArn := aws.ToString(pmt.ProvisionedModelArn)

			// Check for high-capacity provisioned throughput
			if pmt.ModelUnits != nil && *pmt.ModelUnits > 1 {
				risks = append(risks, AIRisk{
					RiskType:       "HighBedrockCapacity",
					Severity:       SeverityMedium,
					Resource:       pmtName,
					Description:    "Bedrock provisioned throughput with " + string(rune(*pmt.ModelUnits)) + " model units - monitor for abuse",
					Recommendation: "Review Bedrock usage; set up cost alerts and usage monitoring",
				})
			}

			// Check commitment term
			if pmt.CommitmentDuration != "" {
				duration := string(pmt.CommitmentDuration)
				if duration == "SixMonths" || duration == "OneYear" {
					risks = append(risks, AIRisk{
						RiskType:       "BedrockLongCommitment",
						Severity:       SeverityLow,
						Resource:       pmtArn,
						Description:    "Bedrock provisioned with " + duration + " commitment",
						Recommendation: "Verify this commitment was intentional and authorized",
					})
				}
			}
		}
	}

	// List custom models (could indicate unauthorized training)
	customModels, err := s.bedrockClient.ListCustomModels(ctx, &bedrock.ListCustomModelsInput{})
	if err == nil && customModels.ModelSummaries != nil {
		for _, model := range customModels.ModelSummaries {
			modelName := aws.ToString(model.ModelName)
			risks = append(risks, AIRisk{
				RiskType:       "CustomBedrockModel",
				Severity:       SeverityMedium,
				Resource:       modelName,
				Description:    "Custom Bedrock model found - verify authorized creation",
				Recommendation: "Audit who created this model and what data was used for training",
			})
		}
	}

	// List model invocation logging
	loggingConfig, err := s.bedrockClient.GetModelInvocationLoggingConfiguration(ctx, &bedrock.GetModelInvocationLoggingConfigurationInput{})
	if err == nil {
		if loggingConfig.LoggingConfig == nil ||
			(loggingConfig.LoggingConfig.CloudWatchConfig == nil &&
				loggingConfig.LoggingConfig.S3Config == nil) {
			risks = append(risks, AIRisk{
				RiskType:       "NoBedrockLogging",
				Severity:       SeverityHigh,
				Resource:       "Bedrock/" + s.region,
				Description:    "Bedrock model invocation logging is not enabled",
				Recommendation: "Enable CloudWatch or S3 logging to detect unauthorized usage",
			})
		}
	}

	return risks, nil
}

// checkRapidProvisioning looks for indicators of rapid resource scaling (attack pattern)
func (s *service) checkRapidProvisioning(ctx context.Context) ([]AIRisk, error) {
	var risks []AIRisk

	// Check for EC2 API throttling (indicates rapid API calls - attack pattern)
	throttleMetric, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/EC2"),
		MetricName: aws.String("ThrottledRequests"),
		StartTime:  aws.Time(aws.ToTime(aws.Time(aws.ToTime(nil)))), // Last 24 hours
		EndTime:    aws.Time(aws.ToTime(nil)),
		Period:     aws.Int32(3600), // 1 hour
		Statistics: []cwTypes.Statistic{cwTypes.StatisticSum},
	})

	if err == nil && throttleMetric.Datapoints != nil {
		for _, dp := range throttleMetric.Datapoints {
			if dp.Sum != nil && *dp.Sum > 100 {
				risks = append(risks, AIRisk{
					RiskType:       "RapidAPIActivity",
					Severity:       SeverityHigh,
					Resource:       "EC2 API",
					Description:    "High EC2 API throttle count detected - possible automated attack",
					Recommendation: "Review CloudTrail for rapid resource provisioning patterns",
				})
				break
			}
		}
	}

	return risks, nil
}
