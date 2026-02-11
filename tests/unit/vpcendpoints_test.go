// Package tests contains unit tests for VPC Endpoints security service.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thirukguru/aws-perimeter/service/vpcendpoints"
)

// TestEndpointStatus tests the GetEndpointStatus struct fields
func TestEndpointStatus(t *testing.T) {
	tests := []struct {
		name           string
		gatewayCount   int
		interfaceCount int
		s3Exists       bool
		dynamoExists   bool
	}{
		{
			name:           "no endpoints",
			gatewayCount:   0,
			interfaceCount: 0,
			s3Exists:       false,
			dynamoExists:   false,
		},
		{
			name:           "s3 endpoint exists",
			gatewayCount:   1,
			interfaceCount: 0,
			s3Exists:       true,
			dynamoExists:   false,
		},
		{
			name:           "both gateway endpoints",
			gatewayCount:   2,
			interfaceCount: 3,
			s3Exists:       true,
			dynamoExists:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &vpcendpoints.EndpointStatus{
				GatewayEndpoints:     tt.gatewayCount,
				InterfaceEndpoints:   tt.interfaceCount,
				S3EndpointExists:     tt.s3Exists,
				DynamoEndpointExists: tt.dynamoExists,
			}
			assert.Equal(t, tt.gatewayCount, status.GatewayEndpoints)
			assert.Equal(t, tt.s3Exists, status.S3EndpointExists)
		})
	}
}

// TestEndpointRisk tests the EndpointRisk struct
func TestEndpointRisk(t *testing.T) {
	risk := vpcendpoints.EndpointRisk{
		EndpointID:     "vpce-12345",
		EndpointType:   "Interface",
		ServiceName:    "com.amazonaws.us-east-1.s3",
		VpcID:          "vpc-12345",
		State:          "available",
		PolicyType:     "full-access",
		IsPrivateDNS:   true,
		Severity:       vpcendpoints.SeverityMedium,
		Description:    "Endpoint allows full access",
		Recommendation: "Apply restrictive endpoint policy",
	}

	assert.Equal(t, "vpce-12345", risk.EndpointID)
	assert.Equal(t, "Interface", risk.EndpointType)
	assert.True(t, risk.IsPrivateDNS)
	assert.Equal(t, vpcendpoints.SeverityMedium, risk.Severity)
}

// TestNATGatewayStatus tests the NATGatewayStatus struct
func TestNATGatewayStatus(t *testing.T) {
	tests := []struct {
		name         string
		natGWCount   int
		natInstCount int
		singleAZRisk bool
	}{
		{
			name:         "single NAT Gateway - single AZ risk",
			natGWCount:   1,
			natInstCount: 0,
			singleAZRisk: true,
		},
		{
			name:         "multiple NAT Gateways - no risk",
			natGWCount:   3,
			natInstCount: 0,
			singleAZRisk: false,
		},
		{
			name:         "legacy NAT Instance detected",
			natGWCount:   0,
			natInstCount: 1,
			singleAZRisk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &vpcendpoints.NATGatewayStatus{
				NATGatewayCount:  tt.natGWCount,
				NATInstanceCount: tt.natInstCount,
				SingleAZRisk:     tt.singleAZRisk,
			}
			assert.Equal(t, tt.singleAZRisk, status.SingleAZRisk)
		})
	}
}

// TestMissingEndpoint tests the MissingEndpoint recommendation
func TestMissingEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		serviceName  string
		wantSeverity string
	}{
		{
			name:         "S3 endpoint missing - critical",
			serviceName:  "s3",
			wantSeverity: vpcendpoints.SeverityCritical,
		},
		{
			name:         "SSM endpoint missing - high",
			serviceName:  "ssm",
			wantSeverity: vpcendpoints.SeverityHigh,
		},
		{
			name:         "ECR endpoint missing - medium",
			serviceName:  "ecr.api",
			wantSeverity: vpcendpoints.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := vpcendpoints.MissingEndpoint{
				ServiceName: tt.serviceName,
				Severity:    tt.wantSeverity,
				TrafficType: "data-plane",
			}
			assert.Equal(t, tt.serviceName, endpoint.ServiceName)
			assert.Equal(t, tt.wantSeverity, endpoint.Severity)
		})
	}
}

// TestNATSecurityRisk tests the NATSecurityRisk struct
func TestNATSecurityRisk(t *testing.T) {
	risk := vpcendpoints.NATSecurityRisk{
		ResourceID:       "nat-12345",
		ResourceType:     "NAT Gateway",
		VpcID:            "vpc-12345",
		SubnetID:         "subnet-12345",
		AvailabilityZone: "us-east-1a",
		PublicIP:         "54.123.45.67",
		IsHighAvailable:  false,
		Severity:         vpcendpoints.SeverityMedium,
		Description:      "Single-AZ NAT Gateway",
		Recommendation:   "Deploy NAT Gateway in multiple AZs",
	}

	assert.Equal(t, "nat-12345", risk.ResourceID)
	assert.Equal(t, "NAT Gateway", risk.ResourceType)
	assert.False(t, risk.IsHighAvailable)
	assert.Equal(t, "54.123.45.67", risk.PublicIP)
}
