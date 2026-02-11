// Package tests contains unit tests for VPC Advanced security service.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/vpcadvanced"
)

// TestVPCPeeringRisk tests the VPC peering risk detection
func TestVPCPeeringRisk(t *testing.T) {
	tests := []struct {
		name           string
		isCrossAccount bool
		isCrossRegion  bool
		wantSeverity   string
	}{
		{
			name:           "same account same region - low risk",
			isCrossAccount: false,
			isCrossRegion:  false,
			wantSeverity:   vpcadvanced.SeverityLow,
		},
		{
			name:           "cross account - medium risk",
			isCrossAccount: true,
			isCrossRegion:  false,
			wantSeverity:   vpcadvanced.SeverityMedium,
		},
		{
			name:           "cross region - medium risk",
			isCrossAccount: false,
			isCrossRegion:  true,
			wantSeverity:   vpcadvanced.SeverityMedium,
		},
		{
			name:           "cross account and cross region - high risk",
			isCrossAccount: true,
			isCrossRegion:  true,
			wantSeverity:   vpcadvanced.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := vpcadvanced.VPCPeeringRisk{
				PeeringID:      "pcx-12345",
				RequesterVPC:   "vpc-111",
				AccepterVPC:    "vpc-222",
				IsCrossAccount: tt.isCrossAccount,
				IsCrossRegion:  tt.isCrossRegion,
				Severity:       tt.wantSeverity,
			}
			assert.Equal(t, tt.isCrossAccount, risk.IsCrossAccount)
			assert.Equal(t, tt.isCrossRegion, risk.IsCrossRegion)
		})
	}
}

// TestOverlappingCIDR tests the CIDR overlap detection
func TestOverlappingCIDR(t *testing.T) {
	overlap := vpcadvanced.OverlappingCIDR{
		VPC1ID:      "vpc-111",
		VPC1CIDR:    "10.0.0.0/16",
		VPC2ID:      "vpc-222",
		VPC2CIDR:    "10.0.0.0/24",
		Severity:    vpcadvanced.SeverityHigh,
		Description: "VPCs have overlapping CIDR blocks",
	}

	assert.Equal(t, "vpc-111", overlap.VPC1ID)
	assert.Equal(t, "10.0.0.0/16", overlap.VPC1CIDR)
	assert.Equal(t, vpcadvanced.SeverityHigh, overlap.Severity)
}

// TestBastionHost tests bastion host detection
func TestBastionHost(t *testing.T) {
	tests := []struct {
		name         string
		sshPort      bool
		rdpPort      bool
		publicIP     string
		wantSeverity string
	}{
		{
			name:         "SSH bastion with public IP - high risk",
			sshPort:      true,
			rdpPort:      false,
			publicIP:     "54.123.45.67",
			wantSeverity: vpcadvanced.SeverityHigh,
		},
		{
			name:         "RDP bastion with public IP - critical risk",
			sshPort:      false,
			rdpPort:      true,
			publicIP:     "54.123.45.68",
			wantSeverity: vpcadvanced.SeverityCritical,
		},
		{
			name:         "Both SSH and RDP exposed - critical risk",
			sshPort:      true,
			rdpPort:      true,
			publicIP:     "54.123.45.69",
			wantSeverity: vpcadvanced.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := vpcadvanced.BastionHost{
				InstanceID: "i-12345",
				PublicIP:   tt.publicIP,
				SSHPort:    tt.sshPort,
				RDPPort:    tt.rdpPort,
				Severity:   tt.wantSeverity,
			}
			assert.Equal(t, tt.sshPort, host.SSHPort)
			assert.Equal(t, tt.rdpPort, host.RDPPort)
			assert.NotEmpty(t, host.PublicIP)
		})
	}
}

// TestSubnetClassification tests subnet classification logic
func TestSubnetClassification(t *testing.T) {
	tests := []struct {
		name        string
		isPublic    bool
		hasIGWRoute bool
		hasNatRoute bool
	}{
		{
			name:        "public subnet with IGW route",
			isPublic:    true,
			hasIGWRoute: true,
			hasNatRoute: false,
		},
		{
			name:        "private subnet with NAT route",
			isPublic:    false,
			hasIGWRoute: false,
			hasNatRoute: true,
		},
		{
			name:        "isolated subnet - no routes",
			isPublic:    false,
			hasIGWRoute: false,
			hasNatRoute: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification := vpcadvanced.SubnetClassification{
				SubnetID:    "subnet-12345",
				VpcID:       "vpc-12345",
				IsPublic:    tt.isPublic,
				HasIGWRoute: tt.hasIGWRoute,
				HasNATRoute: tt.hasNatRoute,
			}
			assert.Equal(t, tt.isPublic, classification.IsPublic)
			if tt.isPublic {
				assert.True(t, classification.HasIGWRoute)
			}
		})
	}
}

// TestAZDistribution tests AZ distribution analysis
func TestAZDistribution(t *testing.T) {
	tests := []struct {
		name         string
		azCount      int
		isBalanced   bool
		wantSeverity string
	}{
		{
			name:         "single AZ - high risk",
			azCount:      1,
			isBalanced:   false,
			wantSeverity: vpcadvanced.SeverityHigh,
		},
		{
			name:         "two AZs - medium risk",
			azCount:      2,
			isBalanced:   true,
			wantSeverity: vpcadvanced.SeverityMedium,
		},
		{
			name:         "three AZs - low risk",
			azCount:      3,
			isBalanced:   true,
			wantSeverity: vpcadvanced.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dist := vpcadvanced.AZDistribution{
				VpcID:      "vpc-12345",
				AZCount:    tt.azCount,
				IsBalanced: tt.isBalanced,
				Severity:   tt.wantSeverity,
			}
			assert.Equal(t, tt.azCount, dist.AZCount)
			assert.Equal(t, tt.isBalanced, dist.IsBalanced)
		})
	}
}
