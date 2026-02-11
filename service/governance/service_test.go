package governance

import "testing"

func TestContainsDenyRegionGuardrail(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Deny","Condition":{"StringNotEquals":{"aws:RequestedRegion":["us-east-1"]}}}]}`
	if !containsDenyRegionGuardrail(policy) {
		t.Fatalf("expected region guardrail to be detected")
	}
}

func TestContainsDenyRootAccess(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Deny","Condition":{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*:root"}}}]}`
	if !containsDenyRootAccess(policy) {
		t.Fatalf("expected root deny to be detected")
	}
}

func TestContainsDenyService(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Deny","Action":["bedrock:*"]}]}`
	if !containsDenyService(policy, "bedrock:") {
		t.Fatalf("expected bedrock deny to be detected")
	}
	if containsDenyService(policy, "sagemaker:") {
		t.Fatalf("did not expect sagemaker deny for this policy")
	}
}
