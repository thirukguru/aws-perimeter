package aidetection

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestGPUInstanceTypes(t *testing.T) {
	testCases := []struct {
		instanceType string
		isGPU        bool
	}{
		{"p3.2xlarge", true},
		{"p4d.24xlarge", true},
		{"p5.48xlarge", true},
		{"g4dn.xlarge", true},
		{"g5.12xlarge", true},
		{"inf2.xlarge", true},
		{"trn1.32xlarge", true},
		{"t3.micro", false},
		{"m5.large", false},
		{"c5.xlarge", false},
		{"r5.2xlarge", false},
	}

	for _, tc := range testCases {
		t.Run(tc.instanceType, func(t *testing.T) {
			isGPU := gpuInstanceTypes[tc.instanceType]
			if isGPU != tc.isGPU {
				t.Errorf("Instance %s: expected GPU=%v, got %v", tc.instanceType, tc.isGPU, isGPU)
			}
		})
	}
}

func TestCredentialPatterns(t *testing.T) {
	testCases := []struct {
		name     string
		text     string
		expected bool
	}{
		{"Valid access key", "AKIAIOSFODNN7EXAMPLE", true},
		{"Temp access key", "ASIAIOSFODNN7EXAMPLE", true},
		{"Invalid key", "XXXAIOSFODNN7EXAMPLE", false},
		{"Short key", "AKIA123", false},
		{"Secret key var", "aws_secret_access_key=xxx", true},
		{"Session token", "AWS_SESSION_TOKEN", true},
		{"Normal text", "hello world", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			for _, pattern := range credentialPatterns {
				if pattern.MatchString(tc.text) {
					matched = true
					break
				}
			}
			if matched != tc.expected {
				t.Errorf("Text %q: expected match=%v, got %v", tc.text, tc.expected, matched)
			}
		})
	}
}

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

func TestAIRiskStruct(t *testing.T) {
	risk := AIRisk{
		RiskType:       "GPUInstanceRunning",
		Severity:       SeverityHigh,
		Resource:       "i-1234567890abcdef0",
		Description:    "GPU instance detected",
		Recommendation: "Verify legitimate use",
	}

	if risk.RiskType != "GPUInstanceRunning" {
		t.Error("RiskType not set correctly")
	}
	if risk.Severity != SeverityHigh {
		t.Error("Severity not set correctly")
	}
	if risk.Resource == "" {
		t.Error("Resource should not be empty")
	}
}

func TestGPUInstanceTypesCoverage(t *testing.T) {
	// Verify all major GPU families are covered
	families := []string{"p2", "p3", "p4", "p5", "g3", "g4", "g5", "inf1", "inf2", "trn1"}

	for _, family := range families {
		found := false
		for instanceType := range gpuInstanceTypes {
			if len(instanceType) >= len(family) && instanceType[:len(family)] == family {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GPU family %s not covered in gpuInstanceTypes", family)
		}
	}
}
