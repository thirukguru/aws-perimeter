package ecrsecurity

import (
	"testing"

	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func TestPolicyHasPublicPrincipal(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		expected bool
	}{
		{
			name:     "principal wildcard string",
			policy:   `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:BatchGetImage"}]}`,
			expected: true,
		},
		{
			name:     "principal wildcard aws map",
			policy:   `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"ecr:BatchGetImage"}]}`,
			expected: true,
		},
		{
			name:     "specific principal only",
			policy:   `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"ecr:BatchGetImage"}]}`,
			expected: false,
		},
		{
			name:     "deny statement ignored",
			policy:   `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"ecr:*"}]}`,
			expected: false,
		},
		{
			name:     "invalid json",
			policy:   `{not-json}`,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyHasPublicPrincipal(tc.policy); got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestRepositoryChecks(t *testing.T) {
	repo := ecrtypes.Repository{
		ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{
			ScanOnPush: false,
		},
		EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
			EncryptionType: ecrtypes.EncryptionTypeAes256,
		},
	}

	if !isMutableTagRepo(repo) {
		t.Fatalf("expected mutable tag repo to be flagged")
	}
	if scanOnPushEnabled(repo) {
		t.Fatalf("expected scanOnPush to be false")
	}
	if kmsEncryptionConfigured(repo) {
		t.Fatalf("expected KMS encryption check to be false")
	}

	repo.ImageTagMutability = ecrtypes.ImageTagMutabilityImmutable
	repo.ImageScanningConfiguration.ScanOnPush = true
	repo.EncryptionConfiguration.EncryptionType = ecrtypes.EncryptionTypeKms

	if isMutableTagRepo(repo) {
		t.Fatalf("expected immutable tag repo to pass")
	}
	if !scanOnPushEnabled(repo) {
		t.Fatalf("expected scanOnPush to be true")
	}
	if !kmsEncryptionConfigured(repo) {
		t.Fatalf("expected KMS encryption check to be true")
	}
}
