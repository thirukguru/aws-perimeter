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

func TestPolicyAllowsBatchGetImageFromWildcard(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"ecr:BatchGetImage"}]}`
	if !policyAllowsBatchGetImageFromWildcard(policy) {
		t.Fatalf("expected wildcard batch-get policy to be detected")
	}

	policyNoBatch := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"ecr:DescribeImages"}]}`
	if policyAllowsBatchGetImageFromWildcard(policyNoBatch) {
		t.Fatalf("did not expect non-batchget action to match")
	}
}

func TestPolicyExternalBatchGetImageAccounts(t *testing.T) {
	policy := `{
		"Statement":[
			{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"ecr:BatchGetImage"},
			{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::999999999999:root","arn:aws:iam::888888888888:root"]},"Action":["ecr:GetDownloadUrlForLayer","ecr:BatchGetImage"]},
			{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"ecr:BatchGetImage"}
		]
	}`
	got := policyExternalBatchGetImageAccounts(policy, "123456789012")
	if len(got) != 2 {
		t.Fatalf("expected 2 external account IDs, got %d (%v)", len(got), got)
	}
	if got[0] != "888888888888" || got[1] != "999999999999" {
		t.Fatalf("unexpected external account IDs: %v", got)
	}
}

func TestRepoSuppressionPatternMatch(t *testing.T) {
	if !repoCoveredBySuppressionPolicy("team/app", false, []string{"team/*"}) {
		t.Fatalf("expected prefix suppression pattern to match repo")
	}
	if repoCoveredBySuppressionPolicy("team/app", false, []string{"prod/*"}) {
		t.Fatalf("did not expect unrelated suppression pattern to match repo")
	}
	if !repoCoveredBySuppressionPolicy("team/app", true, nil) {
		t.Fatalf("expected all=true suppression coverage")
	}
}
