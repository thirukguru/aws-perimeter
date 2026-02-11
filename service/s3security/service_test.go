package s3security

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestIsLikelyTextObject(t *testing.T) {
	tests := []struct {
		key  string
		size int64
		want bool
	}{
		{key: "prod/.env", size: 120, want: true},
		{key: "repo/.git/config", size: 500, want: true},
		{key: "secrets/credentials.txt", size: 4096, want: true},
		{key: "logs/app.log", size: 800_000, want: true},
		{key: "images/photo.jpg", size: 120_000, want: false},
		{key: "bin/dump.dat", size: 3 * 1024 * 1024, want: false},
		{key: "empty/file.txt", size: 0, want: false},
	}

	for _, tt := range tests {
		if got := isLikelyTextObject(tt.key, tt.size); got != tt.want {
			t.Fatalf("isLikelyTextObject(%q, %d) = %v, want %v", tt.key, tt.size, got, tt.want)
		}
	}
}

func TestDetectSensitiveContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantOK   bool
		wantType string
	}{
		{
			name:     "aws access key",
			content:  "aws_access_key_id=AKIA1234567890ABCDEF",
			wantOK:   true,
			wantType: "AWS Access Key",
		},
		{
			name:     "private key",
			content:  "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
			wantOK:   true,
			wantType: "Private Key Material",
		},
		{
			name:     "password assignment",
			content:  `password="supersecretpassword123"`,
			wantOK:   true,
			wantType: "Generic Password Assignment",
		},
		{
			name:     "clean content",
			content:  "hello world",
			wantOK:   false,
			wantType: "",
		},
	}

	for _, tt := range tests {
		gotName, _, gotOK := detectSensitiveContent(tt.content)
		if gotOK != tt.wantOK {
			t.Fatalf("%s: detectSensitiveContent() ok = %v, want %v", tt.name, gotOK, tt.wantOK)
		}
		if gotName != tt.wantType {
			t.Fatalf("%s: detectSensitiveContent() type = %q, want %q", tt.name, gotName, tt.wantType)
		}
	}
}

func TestPolicyAllowsPublicReadOrWrite(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   bool
	}{
		{
			name:   "public get object",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`,
			want:   true,
		},
		{
			name:   "public aws map write",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:PutObject","s3:GetObject"]}]}`,
			want:   true,
		},
		{
			name:   "public but no object read/write",
			policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket"}]}`,
			want:   false,
		},
		{
			name:   "specific principal",
			policy: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject"}]}`,
			want:   false,
		},
	}

	for _, tt := range tests {
		if got := policyAllowsPublicReadOrWrite(tt.policy); got != tt.want {
			t.Fatalf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsCriticalBucket(t *testing.T) {
	if !isCriticalBucket("prod-customer-data", nil) {
		t.Fatalf("expected prod naming convention to be treated as critical")
	}
	if !isCriticalBucket("app-bucket", map[string]string{"classification": "critical"}) {
		t.Fatalf("expected critical classification tag to be treated as critical")
	}
	if isCriticalBucket("dev-temp-bucket", map[string]string{"environment": "dev"}) {
		t.Fatalf("did not expect dev bucket to be treated as critical")
	}
}

func TestEncryptionEnforced(t *testing.T) {
	if encryptionEnforced(nil) {
		t.Fatalf("did not expect nil config to be enforced")
	}
	if encryptionEnforced(&types.ServerSideEncryptionConfiguration{}) {
		t.Fatalf("did not expect empty rules to be enforced")
	}
	if !encryptionEnforced(&types.ServerSideEncryptionConfiguration{
		Rules: []types.ServerSideEncryptionRule{
			{
				ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
					SSEAlgorithm: types.ServerSideEncryptionAes256,
				},
			},
		},
	}) {
		t.Fatalf("expected AES256 encryption rule to be enforced")
	}
	if !encryptionEnforced(&types.ServerSideEncryptionConfiguration{
		Rules: []types.ServerSideEncryptionRule{
			{
				ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
					SSEAlgorithm: types.ServerSideEncryptionAwsKms,
				},
			},
		},
	}) {
		t.Fatalf("expected KMS encryption rule to be enforced")
	}
}
