// Package vpcendpoints provides VPC endpoint and NAT security analysis.
package vpcendpoints

import (
	"context"
	"fmt"
	"strings"

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

// EndpointStatus represents VPC endpoint configuration status
type EndpointStatus struct {
	GatewayEndpoints     int
	InterfaceEndpoints   int
	S3EndpointExists     bool
	DynamoEndpointExists bool
	Severity             string
	Description          string
	Recommendation       string
}

// EndpointRisk represents a VPC endpoint with security issues
type EndpointRisk struct {
	EndpointID     string
	EndpointType   string // "Gateway" or "Interface"
	ServiceName    string
	VpcID          string
	State          string
	PolicyType     string // "Full Access", "Restricted", "Custom"
	IsPrivateDNS   bool
	Severity       string
	Description    string
	Recommendation string
}

// NATGatewayStatus represents NAT Gateway configuration
type NATGatewayStatus struct {
	NATGatewayCount  int
	NATInstanceCount int
	SingleAZRisk     bool
	PublicIPCount    int
	Severity         string
	Description      string
	Recommendation   string
}

// NATSecurityRisk represents NAT-related security issues
type NATSecurityRisk struct {
	ResourceID       string
	ResourceType     string // "NAT Gateway" or "NAT Instance"
	VpcID            string
	SubnetID         string
	AvailabilityZone string
	PublicIP         string
	IsHighAvailable  bool
	Severity         string
	Description      string
	Recommendation   string
}

// MissingEndpoint represents a service that should use VPC endpoints
type MissingEndpoint struct {
	ServiceName    string
	TrafficType    string // "S3", "DynamoDB", "SSM", "Secrets Manager", etc.
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	client *ec2.Client
}

// Service is the interface for VPC endpoint security analysis
type Service interface {
	GetEndpointStatus(ctx context.Context) (*EndpointStatus, error)
	GetEndpointRisks(ctx context.Context) ([]EndpointRisk, error)
	GetNATStatus(ctx context.Context) (*NATGatewayStatus, error)
	GetNATSecurityRisks(ctx context.Context) ([]NATSecurityRisk, error)
	GetMissingEndpoints(ctx context.Context) ([]MissingEndpoint, error)
}

// NewService creates a new VPC endpoints service
func NewService(cfg aws.Config) Service {
	return &service{
		client: ec2.NewFromConfig(cfg),
	}
}

// GetEndpointStatus checks overall VPC endpoint configuration
func (s *service) GetEndpointStatus(ctx context.Context) (*EndpointStatus, error) {
	status := &EndpointStatus{}

	endpoints, err := s.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return nil, err
	}

	for _, ep := range endpoints.VpcEndpoints {
		switch ep.VpcEndpointType {
		case types.VpcEndpointTypeGateway:
			status.GatewayEndpoints++
			serviceName := aws.ToString(ep.ServiceName)
			if strings.Contains(serviceName, "s3") {
				status.S3EndpointExists = true
			}
			if strings.Contains(serviceName, "dynamodb") {
				status.DynamoEndpointExists = true
			}
		case types.VpcEndpointTypeInterface:
			status.InterfaceEndpoints++
		}
	}

	if status.GatewayEndpoints == 0 && status.InterfaceEndpoints == 0 {
		status.Severity = SeverityMedium
		status.Description = "No VPC endpoints configured"
		status.Recommendation = "Create S3 and DynamoDB gateway endpoints to reduce NAT costs and improve security"
	} else if !status.S3EndpointExists {
		status.Severity = SeverityMedium
		status.Description = "S3 gateway endpoint not configured"
		status.Recommendation = "Create S3 gateway endpoint for cost savings and private access"
	} else {
		status.Severity = SeverityLow
		status.Description = fmt.Sprintf("%d gateway and %d interface endpoints configured", status.GatewayEndpoints, status.InterfaceEndpoints)
		status.Recommendation = "Continue monitoring endpoint usage"
	}

	return status, nil
}

// GetEndpointRisks finds VPC endpoints with security issues
func (s *service) GetEndpointRisks(ctx context.Context) ([]EndpointRisk, error) {
	var risks []EndpointRisk

	endpoints, err := s.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return nil, err
	}

	for _, ep := range endpoints.VpcEndpoints {
		var issues []string
		severity := SeverityLow
		policyType := "Unknown"

		// Analyze endpoint policy
		policy := aws.ToString(ep.PolicyDocument)
		if policy != "" {
			if strings.Contains(policy, "\"Principal\":\"*\"") || strings.Contains(policy, "\"Principal\": \"*\"") {
				if strings.Contains(policy, "\"Action\":\"*\"") || strings.Contains(policy, "\"Action\": \"*\"") {
					policyType = "Full Access"
					issues = append(issues, "allows all principals and actions")
					severity = SeverityMedium
				} else {
					policyType = "Custom"
				}
			} else {
				policyType = "Restricted"
			}
		}

		// Check state
		if ep.State != types.StateAvailable {
			issues = append(issues, "not in available state")
			severity = SeverityMedium
		}

		// Interface endpoints without private DNS
		if ep.VpcEndpointType == types.VpcEndpointTypeInterface {
			if ep.PrivateDnsEnabled == nil || !*ep.PrivateDnsEnabled {
				issues = append(issues, "private DNS not enabled")
				if severity == SeverityLow {
					severity = SeverityLow // Just informational
				}
			}
		}

		if len(issues) > 0 {
			risks = append(risks, EndpointRisk{
				EndpointID:     aws.ToString(ep.VpcEndpointId),
				EndpointType:   string(ep.VpcEndpointType),
				ServiceName:    aws.ToString(ep.ServiceName),
				VpcID:          aws.ToString(ep.VpcId),
				State:          string(ep.State),
				PolicyType:     policyType,
				IsPrivateDNS:   ep.PrivateDnsEnabled != nil && *ep.PrivateDnsEnabled,
				Severity:       severity,
				Description:    joinStrings(issues),
				Recommendation: "Review and restrict endpoint policy",
			})
		}
	}

	return risks, nil
}

// GetNATStatus checks NAT Gateway/Instance configuration
func (s *service) GetNATStatus(ctx context.Context) (*NATGatewayStatus, error) {
	status := &NATGatewayStatus{}

	// Count NAT Gateways
	natGateways, err := s.client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		Filter: []types.Filter{
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	})
	if err == nil {
		status.NATGatewayCount = len(natGateways.NatGateways)

		// Check for public IPs
		for _, nat := range natGateways.NatGateways {
			for _, addr := range nat.NatGatewayAddresses {
				if addr.PublicIp != nil {
					status.PublicIPCount++
				}
			}
		}

		// Check AZ distribution
		azs := make(map[string]bool)
		for _, nat := range natGateways.NatGateways {
			// Get subnet AZ
			subnets, _ := s.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
				SubnetIds: []string{aws.ToString(nat.SubnetId)},
			})
			if subnets != nil && len(subnets.Subnets) > 0 {
				azs[aws.ToString(subnets.Subnets[0].AvailabilityZone)] = true
			}
		}
		if len(azs) == 1 && status.NATGatewayCount > 0 {
			status.SingleAZRisk = true
		}
	}

	// Count NAT Instances (EC2 instances acting as NAT)
	natInstances, err := s.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("source-dest-check"),
				Values: []string{"false"},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})
	if err == nil {
		for _, res := range natInstances.Reservations {
			status.NATInstanceCount += len(res.Instances)
		}
	}

	// Determine severity
	if status.NATGatewayCount == 0 && status.NATInstanceCount == 0 {
		status.Severity = SeverityLow
		status.Description = "No NAT resources configured"
		status.Recommendation = "Consider VPC endpoints instead of NAT for AWS services"
	} else if status.NATInstanceCount > 0 {
		status.Severity = SeverityMedium
		status.Description = fmt.Sprintf("%d NAT instances detected (legacy pattern)", status.NATInstanceCount)
		status.Recommendation = "Migrate to NAT Gateway for better availability"
	} else if status.SingleAZRisk {
		status.Severity = SeverityMedium
		status.Description = "NAT Gateways in single AZ - availability risk"
		status.Recommendation = "Deploy NAT Gateway in each AZ for high availability"
	} else {
		status.Severity = SeverityLow
		status.Description = fmt.Sprintf("%d NAT Gateways properly distributed", status.NATGatewayCount)
		status.Recommendation = "Consider VPC endpoints to reduce NAT costs"
	}

	return status, nil
}

// GetNATSecurityRisks finds NAT-related security issues
func (s *service) GetNATSecurityRisks(ctx context.Context) ([]NATSecurityRisk, error) {
	var risks []NATSecurityRisk

	// Analyze NAT Gateways
	natGateways, err := s.client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{})
	if err == nil {
		azGateways := make(map[string]int)

		for _, nat := range natGateways.NatGateways {
			if nat.State != types.NatGatewayStateAvailable {
				continue
			}

			// Get AZ from subnet
			az := ""
			subnets, _ := s.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
				SubnetIds: []string{aws.ToString(nat.SubnetId)},
			})
			if subnets != nil && len(subnets.Subnets) > 0 {
				az = aws.ToString(subnets.Subnets[0].AvailabilityZone)
				azGateways[az]++
			}

			publicIP := ""
			if len(nat.NatGatewayAddresses) > 0 {
				publicIP = aws.ToString(nat.NatGatewayAddresses[0].PublicIp)
			}

			// Check if single AZ (will be verified after counting all)
			risks = append(risks, NATSecurityRisk{
				ResourceID:       aws.ToString(nat.NatGatewayId),
				ResourceType:     "NAT Gateway",
				VpcID:            aws.ToString(nat.VpcId),
				SubnetID:         aws.ToString(nat.SubnetId),
				AvailabilityZone: az,
				PublicIP:         publicIP,
				IsHighAvailable:  false, // Will update later
				Severity:         SeverityLow,
				Description:      "NAT Gateway operational",
				Recommendation:   "Consider VPC endpoints for AWS services",
			})
		}

		// Mark HA status
		for i := range risks {
			if risks[i].ResourceType == "NAT Gateway" {
				risks[i].IsHighAvailable = len(azGateways) > 1
				if !risks[i].IsHighAvailable && len(azGateways) == 1 {
					risks[i].Severity = SeverityMedium
					risks[i].Description = "Single-AZ NAT Gateway - availability risk"
					risks[i].Recommendation = "Deploy NAT Gateway in multiple AZs"
				}
			}
		}
	}

	// Analyze NAT Instances
	natInstances, err := s.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("source-dest-check"),
				Values: []string{"false"},
			},
		},
	})
	if err == nil {
		for _, res := range natInstances.Reservations {
			for _, inst := range res.Instances {
				if inst.State.Name != types.InstanceStateNameRunning {
					continue
				}

				risks = append(risks, NATSecurityRisk{
					ResourceID:       aws.ToString(inst.InstanceId),
					ResourceType:     "NAT Instance",
					VpcID:            aws.ToString(inst.VpcId),
					SubnetID:         aws.ToString(inst.SubnetId),
					AvailabilityZone: aws.ToString(inst.Placement.AvailabilityZone),
					PublicIP:         aws.ToString(inst.PublicIpAddress),
					IsHighAvailable:  false,
					Severity:         SeverityMedium,
					Description:      "NAT Instance is legacy pattern - less reliable than NAT Gateway",
					Recommendation:   "Migrate to NAT Gateway for managed high availability",
				})
			}
		}
	}

	return risks, nil
}

// GetMissingEndpoints identifies AWS services that should use VPC endpoints
func (s *service) GetMissingEndpoints(ctx context.Context) ([]MissingEndpoint, error) {
	var missing []MissingEndpoint

	// Get existing endpoints
	endpoints, err := s.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})

	existingServices := make(map[string]bool)
	if err == nil && endpoints != nil && endpoints.VpcEndpoints != nil {
		for _, ep := range endpoints.VpcEndpoints {
			serviceName := aws.ToString(ep.ServiceName)
			existingServices[serviceName] = true
		}
	}

	// Recommended endpoints for security and cost
	recommended := []struct {
		Pattern     string
		ServiceName string
		Reason      string
		Severity    string
	}{
		{"s3", "S3", "High traffic, cost savings, private access", SeverityMedium},
		{"dynamodb", "DynamoDB", "Private access for database traffic", SeverityMedium},
		{"ssm", "SSM", "Session Manager without internet", SeverityMedium},
		{"ssmmessages", "SSM Messages", "Required for SSM Session Manager", SeverityLow},
		{"ec2messages", "EC2 Messages", "Required for SSM", SeverityLow},
		{"secretsmanager", "Secrets Manager", "Private secrets access", SeverityMedium},
		{"kms", "KMS", "Private key management", SeverityMedium},
		{"logs", "CloudWatch Logs", "Private log delivery", SeverityLow},
		{"ecr.api", "ECR API", "Private container registry", SeverityMedium},
		{"ecr.dkr", "ECR Docker", "Private container pulls", SeverityMedium},
	}

	for _, rec := range recommended {
		found := false
		for svc := range existingServices {
			if strings.Contains(strings.ToLower(svc), rec.Pattern) {
				found = true
				break
			}
		}

		if !found {
			missing = append(missing, MissingEndpoint{
				ServiceName:    rec.ServiceName,
				TrafficType:    rec.Reason,
				Severity:       rec.Severity,
				Description:    fmt.Sprintf("No VPC endpoint for %s", rec.ServiceName),
				Recommendation: fmt.Sprintf("Create VPC endpoint for %s - %s", rec.ServiceName, rec.Reason),
			})
		}
	}

	return missing, nil
}

func joinStrings(s []string) string {
	if len(s) == 0 {
		return ""
	}
	result := s[0]
	for i := 1; i < len(s); i++ {
		result += ", " + s[i]
	}
	return result
}
