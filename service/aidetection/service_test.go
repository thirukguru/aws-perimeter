package aidetection

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
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

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type mockCloudTrailEvent struct {
	Username        string
	CloudTrailEvent string
}

func usersToEvents(users []string) []mockCloudTrailEvent {
	events := make([]mockCloudTrailEvent, 0, len(users))
	for _, u := range users {
		events = append(events, mockCloudTrailEvent{Username: u})
	}
	return events
}

func newMockCloudTrailService(eventUsers map[string][]mockCloudTrailEvent) *service {
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()
			payload := string(body)

			eventName := ""
			for name := range eventUsers {
				if strings.Contains(payload, `"AttributeValue":"`+name+`"`) {
					eventName = name
					break
				}
			}

			mockEvents := eventUsers[eventName]
			events := make([]map[string]string, 0, len(mockEvents))
			for _, ev := range mockEvents {
				item := map[string]string{"Username": ev.Username}
				if ev.CloudTrailEvent != "" {
					item["CloudTrailEvent"] = ev.CloudTrailEvent
				}
				events = append(events, item)
			}

			respPayload, _ := json.Marshal(map[string]any{"Events": events})
			return &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/x-amz-json-1.1"},
				},
				Body:    io.NopCloser(bytes.NewReader(respPayload)),
				Request: req,
			}, nil
		}),
	}

	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", "TOKEN"),
		HTTPClient:  httpClient,
		EndpointResolverWithOptions: aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					URL:           "https://mock.cloudtrail.local",
					SigningRegion: region,
				}, nil
			},
		),
	}

	return &service{
		cloudtrailClient: cloudtrail.NewFromConfig(cfg, func(o *cloudtrail.Options) {
			o.RetryMaxAttempts = 1
		}),
	}
}

func TestCheckLateralMovement_MultiDigitCountFormatting(t *testing.T) {
	users := make([]string, 12)
	for i := range users {
		users[i] = "alice"
	}
	svc := newMockCloudTrailService(map[string][]mockCloudTrailEvent{
		"AssumeRole": usersToEvents(users),
	})

	risks, err := svc.checkLateralMovement(context.Background())
	if err != nil {
		t.Fatalf("checkLateralMovement returned error: %v", err)
	}
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}

	r := risks[0]
	if r.RiskType != "LateralMovement" {
		t.Fatalf("expected risk type LateralMovement, got %s", r.RiskType)
	}
	if r.Resource != "alice" {
		t.Fatalf("expected resource alice, got %s", r.Resource)
	}
	if !strings.Contains(r.Description, "12+ roles") {
		t.Fatalf("expected multi-digit count in description, got %q", r.Description)
	}
}

func TestCheckRapidAdminAccess_MultiDigitCountFormatting(t *testing.T) {
	users := make([]string, 10)
	for i := range users {
		users[i] = "bob"
	}
	svc := newMockCloudTrailService(map[string][]mockCloudTrailEvent{
		"AttachUserPolicy": usersToEvents(users),
		"CreateAccessKey":  usersToEvents([]string{"bob", "bob"}),
	})

	risks, err := svc.checkRapidAdminAccess(context.Background())
	if err != nil {
		t.Fatalf("checkRapidAdminAccess returned error: %v", err)
	}
	if len(risks) != 1 {
		t.Fatalf("expected 1 risk, got %d", len(risks))
	}

	r := risks[0]
	if r.RiskType != "RapidAdminAccess" {
		t.Fatalf("expected risk type RapidAdminAccess, got %s", r.RiskType)
	}
	if r.Resource != "bob" {
		t.Fatalf("expected resource bob, got %s", r.Resource)
	}
	if !strings.Contains(r.Description, "12 admin actions") {
		t.Fatalf("expected multi-digit count in description, got %q", r.Description)
	}
}

func TestCheckCloudTrailGaps_DetectsStopDeleteAndUpdate(t *testing.T) {
	svc := newMockCloudTrailService(map[string][]mockCloudTrailEvent{
		"StopLogging": usersToEvents([]string{"eve"}),
		"DeleteTrail": usersToEvents([]string{"mallory"}),
		"UpdateTrail": {
			{
				Username:        "trent",
				CloudTrailEvent: `{"requestParameters":{"isMultiRegionTrail":false}}`,
			},
		},
	})

	risks, err := svc.checkCloudTrailGaps(context.Background())
	if err != nil {
		t.Fatalf("checkCloudTrailGaps returned error: %v", err)
	}
	if len(risks) != 3 {
		t.Fatalf("expected 3 risks, got %d", len(risks))
	}

	seen := map[string]bool{}
	for _, risk := range risks {
		seen[risk.RiskType] = true
	}

	for _, riskType := range []string{"CloudTrailStopped", "CloudTrailDeleted", "CloudTrailModified"} {
		if !seen[riskType] {
			t.Fatalf("expected risk type %s to be present", riskType)
		}
	}
}

func TestCheckCloudTrailGaps_NoEventsNoRisks(t *testing.T) {
	svc := newMockCloudTrailService(map[string][]mockCloudTrailEvent{})

	risks, err := svc.checkCloudTrailGaps(context.Background())
	if err != nil {
		t.Fatalf("checkCloudTrailGaps returned error: %v", err)
	}
	if len(risks) != 0 {
		t.Fatalf("expected 0 risks, got %d", len(risks))
	}
}

func TestCheckCloudTrailGaps_BenignUpdateTrailIgnored(t *testing.T) {
	svc := newMockCloudTrailService(map[string][]mockCloudTrailEvent{
		"UpdateTrail": {
			{
				Username:        "alice",
				CloudTrailEvent: `{"requestParameters":{"isMultiRegionTrail":true,"includeGlobalServiceEvents":true,"enableLogFileValidation":true}}`,
			},
		},
	})

	risks, err := svc.checkCloudTrailGaps(context.Background())
	if err != nil {
		t.Fatalf("checkCloudTrailGaps returned error: %v", err)
	}
	if len(risks) != 0 {
		t.Fatalf("expected 0 risks, got %d", len(risks))
	}
}
