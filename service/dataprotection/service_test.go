package dataprotection

import "testing"

func TestIsCrossRegionVaultArn(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		region   string
		expected bool
	}{
		{
			name:     "different region",
			arn:      "arn:aws:backup:us-west-2:123456789012:backup-vault:dr-vault",
			region:   "us-east-1",
			expected: true,
		},
		{
			name:     "same region",
			arn:      "arn:aws:backup:us-east-1:123456789012:backup-vault:primary",
			region:   "us-east-1",
			expected: false,
		},
		{
			name:     "invalid arn",
			arn:      "not-an-arn",
			region:   "us-east-1",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isCrossRegionVaultArn(tc.arn, tc.region)
			if got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestHasProtectedType(t *testing.T) {
	types := map[string]bool{
		"RDS":              true,
		"AWS::EC2::VOLUME": true,
		"EFS":              true,
	}

	if !hasProtectedType(types, "RDS") {
		t.Fatalf("expected RDS to be present")
	}
	if !hasProtectedType(types, "EC2") {
		t.Fatalf("expected EC2 to match composite type")
	}
	if !hasProtectedType(types, "EFS") {
		t.Fatalf("expected EFS to be present")
	}
	if hasProtectedType(types, "DYNAMODB") {
		t.Fatalf("did not expect DYNAMODB to be present")
	}
}
