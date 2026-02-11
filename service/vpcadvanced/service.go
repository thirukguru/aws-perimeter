// Package vpcadvanced provides VPC peering, bastion, and subnet security analysis.
package vpcadvanced

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

// VPCPeeringRisk represents VPC peering security issues
type VPCPeeringRisk struct {
	PeeringID      string
	RequesterVPC   string
	AccepterVPC    string
	RequesterCIDR  string
	AccepterCIDR   string
	IsCrossAccount bool
	IsCrossRegion  bool
	Status         string
	Severity       string
	Description    string
	Recommendation string
}

// OverlappingCIDR represents overlapping CIDR blocks
type OverlappingCIDR struct {
	VPC1ID      string
	VPC1CIDR    string
	VPC2ID      string
	VPC2CIDR    string
	Severity    string
	Description string
}

// BastionHost represents a detected bastion/jump host
type BastionHost struct {
	InstanceID     string
	InstanceName   string
	PublicIP       string
	SSHPort        bool
	RDPPort        bool
	SubnetType     string
	SecurityGroups []string
	IsHardened     bool
	Severity       string
	Description    string
	Recommendation string
}

// SubnetClassification represents subnet public/private classification
type SubnetClassification struct {
	SubnetID         string
	SubnetName       string
	VpcID            string
	AvailabilityZone string
	CIDRBlock        string
	IsPublic         bool
	HasIGWRoute      bool
	HasNATRoute      bool
	InstanceCount    int
	Severity         string
	Description      string
	Recommendation   string
}

// AZDistribution represents availability zone distribution issues
type AZDistribution struct {
	VpcID          string
	VpcName        string
	AZCount        int
	SubnetsPerAZ   map[string]int
	IsBalanced     bool
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	client *ec2.Client
}

// Service is the interface for advanced VPC security analysis
type Service interface {
	GetVPCPeeringRisks(ctx context.Context) ([]VPCPeeringRisk, error)
	GetOverlappingCIDRs(ctx context.Context) ([]OverlappingCIDR, error)
	GetBastionHosts(ctx context.Context) ([]BastionHost, error)
	GetSubnetClassification(ctx context.Context) ([]SubnetClassification, error)
	GetAZDistribution(ctx context.Context) ([]AZDistribution, error)
}

// NewService creates a new advanced VPC service
func NewService(cfg aws.Config) Service {
	return &service{
		client: ec2.NewFromConfig(cfg),
	}
}

// GetVPCPeeringRisks analyzes VPC peering connections for security issues
func (s *service) GetVPCPeeringRisks(ctx context.Context) ([]VPCPeeringRisk, error) {
	var risks []VPCPeeringRisk

	peerings, err := s.client.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{})
	if err != nil {
		return nil, err
	}

	for _, peer := range peerings.VpcPeeringConnections {
		if peer.Status.Code != types.VpcPeeringConnectionStateReasonCodeActive {
			continue
		}

		requesterVPC := aws.ToString(peer.RequesterVpcInfo.VpcId)
		accepterVPC := aws.ToString(peer.AccepterVpcInfo.VpcId)
		requesterCIDR := aws.ToString(peer.RequesterVpcInfo.CidrBlock)
		accepterCIDR := aws.ToString(peer.AccepterVpcInfo.CidrBlock)
		requesterOwner := aws.ToString(peer.RequesterVpcInfo.OwnerId)
		accepterOwner := aws.ToString(peer.AccepterVpcInfo.OwnerId)
		requesterRegion := aws.ToString(peer.RequesterVpcInfo.Region)
		accepterRegion := aws.ToString(peer.AccepterVpcInfo.Region)

		isCrossAccount := requesterOwner != accepterOwner
		isCrossRegion := requesterRegion != accepterRegion

		severity := SeverityLow
		var issues []string

		if isCrossAccount {
			severity = SeverityMedium
			issues = append(issues, "cross-account peering")
		}

		if isCrossRegion {
			if severity == SeverityLow {
				severity = SeverityMedium
			}
			issues = append(issues, "cross-region peering")
		}

		// Check for overly permissive route tables (all traffic)
		// This would require checking route tables - simplified here

		description := "VPC peering active"
		if len(issues) > 0 {
			description = "VPC peering with " + strings.Join(issues, ", ")
		}

		risks = append(risks, VPCPeeringRisk{
			PeeringID:      aws.ToString(peer.VpcPeeringConnectionId),
			RequesterVPC:   requesterVPC,
			AccepterVPC:    accepterVPC,
			RequesterCIDR:  requesterCIDR,
			AccepterCIDR:   accepterCIDR,
			IsCrossAccount: isCrossAccount,
			IsCrossRegion:  isCrossRegion,
			Status:         string(peer.Status.Code),
			Severity:       severity,
			Description:    description,
			Recommendation: "Review peering route tables for least-privilege access",
		})
	}

	return risks, nil
}

// GetOverlappingCIDRs finds VPCs with overlapping CIDR blocks
func (s *service) GetOverlappingCIDRs(ctx context.Context) ([]OverlappingCIDR, error) {
	var overlaps []OverlappingCIDR

	vpcs, err := s.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}

	// Compare each VPC against others
	for i := 0; i < len(vpcs.Vpcs); i++ {
		for j := i + 1; j < len(vpcs.Vpcs); j++ {
			vpc1 := vpcs.Vpcs[i]
			vpc2 := vpcs.Vpcs[j]

			cidr1 := aws.ToString(vpc1.CidrBlock)
			cidr2 := aws.ToString(vpc2.CidrBlock)

			if cidrsOverlap(cidr1, cidr2) {
				overlaps = append(overlaps, OverlappingCIDR{
					VPC1ID:      aws.ToString(vpc1.VpcId),
					VPC1CIDR:    cidr1,
					VPC2ID:      aws.ToString(vpc2.VpcId),
					VPC2CIDR:    cidr2,
					Severity:    SeverityHigh,
					Description: "Overlapping CIDRs prevent VPC peering/Transit Gateway",
				})
			}
		}
	}

	return overlaps, nil
}

// GetBastionHosts detects bastion/jump hosts
func (s *service) GetBastionHosts(ctx context.Context) ([]BastionHost, error) {
	var bastions []BastionHost

	// Find instances with SSH/RDP open from public IPs
	instances, err := s.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	for _, res := range instances.Reservations {
		for _, inst := range res.Instances {
			// Must have public IP
			if inst.PublicIpAddress == nil {
				continue
			}

			instanceName := getInstanceName(inst.Tags)
			nameLower := strings.ToLower(instanceName)

			// Check if it looks like a bastion
			isLikelyBastion := strings.Contains(nameLower, "bastion") ||
				strings.Contains(nameLower, "jump") ||
				strings.Contains(nameLower, "ssh") ||
				strings.Contains(nameLower, "gateway")

			// Check security groups for SSH/RDP
			hasSSH := false
			hasRDP := false
			var sgIDs []string

			for _, sg := range inst.SecurityGroups {
				sgID := aws.ToString(sg.GroupId)
				sgIDs = append(sgIDs, sgID)

				// Check SG rules
				sgDetails, _ := s.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{sgID},
				})
				if sgDetails != nil && len(sgDetails.SecurityGroups) > 0 {
					for _, rule := range sgDetails.SecurityGroups[0].IpPermissions {
						fromPort := aws.ToInt32(rule.FromPort)
						toPort := aws.ToInt32(rule.ToPort)

						// Check for internet access
						hasInternet := false
						for _, ipRange := range rule.IpRanges {
							if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
								hasInternet = true
								break
							}
						}

						if hasInternet {
							if fromPort <= 22 && toPort >= 22 {
								hasSSH = true
							}
							if fromPort <= 3389 && toPort >= 3389 {
								hasRDP = true
							}
						}
					}
				}
			}

			// If it has SSH/RDP from internet and looks like bastion
			if (hasSSH || hasRDP) && (isLikelyBastion || hasSSH) {
				severity := SeverityMedium
				description := "Detected bastion/jump host"

				// Check hardening
				isHardened := true
				if hasSSH && hasRDP {
					isHardened = false
					description = "Bastion with both SSH and RDP exposed"
				}

				bastions = append(bastions, BastionHost{
					InstanceID:     aws.ToString(inst.InstanceId),
					InstanceName:   instanceName,
					PublicIP:       aws.ToString(inst.PublicIpAddress),
					SSHPort:        hasSSH,
					RDPPort:        hasRDP,
					SubnetType:     "PUBLIC",
					SecurityGroups: sgIDs,
					IsHardened:     isHardened,
					Severity:       severity,
					Description:    description,
					Recommendation: "Enable Session Manager, restrict source IPs, enable logging",
				})
			}
		}
	}

	return bastions, nil
}

// GetSubnetClassification classifies subnets as public or private
func (s *service) GetSubnetClassification(ctx context.Context) ([]SubnetClassification, error) {
	var classifications []SubnetClassification

	// Get all subnets
	subnets, err := s.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		return nil, err
	}

	// Get route tables
	routeTables, err := s.client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{})
	rtMap := make(map[string]*types.RouteTable)
	if err == nil && routeTables != nil && routeTables.RouteTables != nil {
		for i := range routeTables.RouteTables {
			for _, assoc := range routeTables.RouteTables[i].Associations {
				if assoc.SubnetId != nil {
					rtMap[aws.ToString(assoc.SubnetId)] = &routeTables.RouteTables[i]
				}
			}
		}
	}

	// Get internet gateways
	igwVPCs := make(map[string]bool)
	igws, err := s.client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{})
	if err == nil && igws != nil && igws.InternetGateways != nil {
		for _, igw := range igws.InternetGateways {
			for _, attach := range igw.Attachments {
				igwVPCs[aws.ToString(attach.VpcId)] = true
			}
		}
	}

	for _, subnet := range subnets.Subnets {
		subnetID := aws.ToString(subnet.SubnetId)
		vpcID := aws.ToString(subnet.VpcId)

		hasIGWRoute := false
		hasNATRoute := false

		// Check routes
		if rt, ok := rtMap[subnetID]; ok {
			for _, route := range rt.Routes {
				if route.GatewayId != nil && strings.HasPrefix(aws.ToString(route.GatewayId), "igw-") {
					hasIGWRoute = true
				}
				if route.NatGatewayId != nil {
					hasNATRoute = true
				}
			}
		}

		isPublic := hasIGWRoute && igwVPCs[vpcID]
		subnetName := getSubnetName(subnet.Tags)

		severity := SeverityLow
		description := "Private subnet"
		recommendation := "Ensure resources don't need internet access"

		if isPublic {
			description = "Public subnet (has IGW route)"
			recommendation = "Ensure only necessary resources are in public subnets"
		}

		// Count instances in subnet
		instanceCount := 0
		instances, _ := s.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			Filters: []types.Filter{
				{Name: aws.String("subnet-id"), Values: []string{subnetID}},
				{Name: aws.String("instance-state-name"), Values: []string{"running"}},
			},
		})
		if instances != nil {
			for _, res := range instances.Reservations {
				instanceCount += len(res.Instances)
			}
		}

		classifications = append(classifications, SubnetClassification{
			SubnetID:         subnetID,
			SubnetName:       subnetName,
			VpcID:            vpcID,
			AvailabilityZone: aws.ToString(subnet.AvailabilityZone),
			CIDRBlock:        aws.ToString(subnet.CidrBlock),
			IsPublic:         isPublic,
			HasIGWRoute:      hasIGWRoute,
			HasNATRoute:      hasNATRoute,
			InstanceCount:    instanceCount,
			Severity:         severity,
			Description:      description,
			Recommendation:   recommendation,
		})
	}

	return classifications, nil
}

// GetAZDistribution checks AZ distribution for VPCs
func (s *service) GetAZDistribution(ctx context.Context) ([]AZDistribution, error) {
	var distributions []AZDistribution

	vpcs, err := s.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}

	subnets, err := s.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})

	// Group subnets by VPC and AZ
	vpcSubnets := make(map[string]map[string]int)
	if err == nil && subnets != nil && subnets.Subnets != nil {
		for _, subnet := range subnets.Subnets {
			vpcID := aws.ToString(subnet.VpcId)
			az := aws.ToString(subnet.AvailabilityZone)

			if vpcSubnets[vpcID] == nil {
				vpcSubnets[vpcID] = make(map[string]int)
			}
			vpcSubnets[vpcID][az]++
		}
	}

	for _, vpc := range vpcs.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		vpcName := getVPCName(vpc.Tags)

		azMap := vpcSubnets[vpcID]
		if azMap == nil {
			azMap = make(map[string]int)
		}

		azCount := len(azMap)
		isBalanced := azCount >= 2

		severity := SeverityLow
		description := fmt.Sprintf("Subnets in %d AZs", azCount)
		recommendation := "Maintain multi-AZ architecture"

		if azCount == 1 {
			severity = SeverityMedium
			description = "Single-AZ deployment - availability risk"
			recommendation = "Create subnets in multiple AZs"
		} else if azCount == 0 {
			severity = SeverityLow
			description = "No subnets"
		}

		distributions = append(distributions, AZDistribution{
			VpcID:          vpcID,
			VpcName:        vpcName,
			AZCount:        azCount,
			SubnetsPerAZ:   azMap,
			IsBalanced:     isBalanced,
			Severity:       severity,
			Description:    description,
			Recommendation: recommendation,
		})
	}

	return distributions, nil
}

// Helper functions
func getInstanceName(tags []types.Tag) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == "Name" {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}

func getSubnetName(tags []types.Tag) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == "Name" {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}

func getVPCName(tags []types.Tag) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == "Name" {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}

// cidrsOverlap checks if two CIDR blocks overlap (simplified check)
func cidrsOverlap(cidr1, cidr2 string) bool {
	// Simple check - if they start with the same prefix, they may overlap
	// A full implementation would parse the CIDR and check IP ranges
	if cidr1 == cidr2 {
		return true
	}

	// Check for common private ranges that would conflict
	parts1 := strings.Split(cidr1, ".")
	parts2 := strings.Split(cidr2, ".")

	if len(parts1) < 2 || len(parts2) < 2 {
		return false
	}

	// Same first two octets likely overlap for typical /16 VPCs
	if parts1[0] == parts2[0] && parts1[1] == parts2[1] {
		return true
	}

	return false
}
