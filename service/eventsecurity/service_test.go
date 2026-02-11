package eventsecurity

import (
	"testing"

	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
)

func TestIsStepFunctionLoggingDisabled(t *testing.T) {
	if !isStepFunctionLoggingDisabled(nil) {
		t.Fatalf("expected nil logging config to be disabled")
	}

	cfgOff := &sfntypes.LoggingConfiguration{Level: sfntypes.LogLevelOff}
	if !isStepFunctionLoggingDisabled(cfgOff) {
		t.Fatalf("expected OFF logging level to be disabled")
	}

	cfgNoDest := &sfntypes.LoggingConfiguration{Level: sfntypes.LogLevelError}
	if !isStepFunctionLoggingDisabled(cfgNoDest) {
		t.Fatalf("expected logging config without destination to be disabled")
	}

	cfgEnabled := &sfntypes.LoggingConfiguration{
		Level: sfntypes.LogLevelAll,
		Destinations: []sfntypes.LogDestination{
			{},
		},
	}
	if isStepFunctionLoggingDisabled(cfgEnabled) {
		t.Fatalf("expected logging with destination to be enabled")
	}
}

func TestHasPublicPrincipal(t *testing.T) {
	publicDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"events:PutEvents"}]}`
	if !hasPublicPrincipal(publicDoc) {
		t.Fatalf("expected public principal to be detected")
	}

	publicMapDoc := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`
	if !hasPublicPrincipal(publicMapDoc) {
		t.Fatalf("expected AWS wildcard principal to be detected")
	}

	privateDoc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"events:PutEvents"}]}`
	if hasPublicPrincipal(privateDoc) {
		t.Fatalf("did not expect non-wildcard principal to be public")
	}
}

func TestExtractRoleName(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/service-role/MyRole"
	if got := extractRoleName(roleARN); got != "MyRole" {
		t.Fatalf("unexpected role name: %s", got)
	}
}
