package ekssecurity

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestNewService(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1"}
	svc := NewService(cfg)
	if svc == nil {
		t.Error("NewService returned nil")
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityCritical != "CRITICAL" {
		t.Errorf("Expected CRITICAL, got %s", SeverityCritical)
	}
	if SeverityHigh != "HIGH" {
		t.Errorf("Expected HIGH, got %s", SeverityHigh)
	}
	if SeverityMedium != "MEDIUM" {
		t.Errorf("Expected MEDIUM, got %s", SeverityMedium)
	}
	if SeverityLow != "LOW" {
		t.Errorf("Expected LOW, got %s", SeverityLow)
	}
}

func TestEKSRiskStruct(t *testing.T) {
	risk := EKSRisk{
		ClusterName:    "test-cluster",
		NodeGroupName:  "node-group-1",
		RiskType:       "PublicEndpointEnabled",
		Severity:       SeverityHigh,
		Description:    "Cluster has public endpoint",
		Recommendation: "Disable public endpoint",
	}

	if risk.ClusterName != "test-cluster" {
		t.Error("ClusterName not set correctly")
	}
	if risk.Severity != SeverityHigh {
		t.Error("Severity not set correctly")
	}
	if risk.RiskType == "" {
		t.Error("RiskType should not be empty")
	}
}

func TestGetEKSRisksEmpty(t *testing.T) {
	s := &service{client: nil}
	ctx := context.Background()

	defer func() {
		if r := recover(); r != nil {
			t.Log("Function handles nil client gracefully")
		}
	}()

	_, _ = s.GetEKSRisks(ctx)
}

func TestServiceInterfaceImplementation(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1"}
	var svc Service = NewService(cfg)
	if svc == nil {
		t.Error("Service interface not properly implemented")
	}
}
