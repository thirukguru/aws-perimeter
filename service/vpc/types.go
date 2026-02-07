// Package vpc provides security analysis for AWS VPC resources.
package vpc

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Severity levels for security findings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// EC2ClientAPI defines the EC2 client methods used by this service.
type EC2ClientAPI interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeNetworkAcls(ctx context.Context, params *ec2.DescribeNetworkAclsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
	DescribeFlowLogs(ctx context.Context, params *ec2.DescribeFlowLogsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error)
	DescribeVpcs(ctx context.Context, params *ec2.DescribeVpcsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// Service defines the VPC security analysis interface.
type Service interface {
	GetSecurityGroupRisks(ctx context.Context) ([]SGRisk, error)
	GetUnusedSecurityGroups(ctx context.Context) ([]UnusedSG, error)
	GetPublicExposureRisks(ctx context.Context) ([]ExposureRisk, error)
	GetNACLRisks(ctx context.Context) ([]NACLRisk, error)
	GetVPCFlowLogStatus(ctx context.Context) ([]FlowLogStatus, error)
	// Phase T: Nation-State Threat Detection
	GetManagementExposureRisks(ctx context.Context) ([]ManagementExposure, error)
	GetPlaintextProtocolRisks(ctx context.Context) ([]PlaintextRisk, error)
	GetIMDSv1Risks(ctx context.Context) ([]IMDSv1Risk, error)
	GetNetworkApplianceRisks(ctx context.Context) ([]NetworkAppliance, error)
	GetManagementSubnetRisks(ctx context.Context) ([]ManagementSubnetRisk, error)
}

type service struct {
	client EC2ClientAPI
}

// SGRisk represents a security group with risky configuration.
type SGRisk struct {
	SecurityGroupID   string
	SecurityGroupName string
	VpcID             string
	RiskType          string // e.g., "OPEN_SSH", "OPEN_RDP", "OPEN_DB_PORT"
	Severity          string // CRITICAL, HIGH, MEDIUM, LOW
	Port              int32
	Protocol          string
	SourceCIDR        string // The offending CIDR (e.g., "0.0.0.0/0")
	Description       string
	Recommendation    string
	AffectedResources []string // Instance IDs, ENI IDs attached to this SG
}

// UnusedSG represents a security group not attached to any resources.
type UnusedSG struct {
	SecurityGroupID   string
	SecurityGroupName string
	VpcID             string
	Description       string
}

// ExposureRisk represents an instance with public exposure.
type ExposureRisk struct {
	InstanceID       string
	InstanceName     string
	PublicIP         string
	SecurityGroupIDs []string
	OpenPorts        []int32
	Severity         string
	Description      string
	Recommendation   string
}

// NACLRisk represents a network ACL with risky rules.
type NACLRisk struct {
	NetworkAclID string
	VpcID        string
	SubnetIDs    []string
	RuleNumber   int32
	IsEgress     bool
	Protocol     string
	PortRange    string
	CidrBlock    string
	RuleAction   string
	Severity     string
	Description  string
}

// FlowLogStatus represents VPC Flow Log configuration status.
type FlowLogStatus struct {
	VpcID           string
	VpcName         string
	FlowLogsEnabled bool
	FlowLogIDs      []string
	Severity        string
	Recommendation  string
}

// ManagementExposure represents EC2 instances with exposed admin interfaces.
// Reference: AWS Threat Intel - GRU Sandworm campaign targeting network edge devices.
type ManagementExposure struct {
	InstanceID     string
	InstanceName   string
	PublicIP       string
	ExposedPorts   []int32
	SecurityGroups []string
	Severity       string
	Description    string
	Recommendation string
}

// PlaintextRisk represents security groups allowing plaintext protocols.
// Reference: AWS Threat Intel - credential harvesting via traffic interception.
type PlaintextRisk struct {
	SecurityGroupID   string
	SecurityGroupName string
	VpcID             string
	Protocol          string
	Port              int32
	SourceCIDR        string
	Severity          string
	Description       string
	Recommendation    string
}

// IMDSv1Risk represents EC2 instances with IMDSv1 enabled (credential theft risk).
type IMDSv1Risk struct {
	InstanceID     string
	InstanceName   string
	IMDSv1Enabled  bool
	Severity       string
	Description    string
	Recommendation string
}

// NetworkAppliance represents EC2 running VPN/firewall appliance software.
// Reference: AWS Threat Intel - GRU Sandworm campaign targets network appliances.
type NetworkAppliance struct {
	InstanceID       string
	InstanceName     string
	AMIID            string
	AMIName          string
	ApplianceType    string // "VPN", "Firewall", "Router", "NAT"
	PublicIP         string
	IsInternetFacing bool
	Severity         string
	Description      string
	Recommendation   string
}

// ManagementSubnetRisk represents instances with management ports in public subnets.
type ManagementSubnetRisk struct {
	InstanceID       string
	InstanceName     string
	SubnetID         string
	SubnetType       string // "PUBLIC", "PRIVATE"
	ExposedMgmtPorts []int32
	PublicIP         string
	Severity         string
	Description      string
	Recommendation   string
}

// NewService creates a new VPC security service.
func NewService(cfg aws.Config) Service {
	return &service{
		client: ec2.NewFromConfig(cfg),
	}
}

// NewServiceWithClient creates a new VPC service with a provided client (for testing).
func NewServiceWithClient(client EC2ClientAPI) Service {
	return &service{
		client: client,
	}
}
