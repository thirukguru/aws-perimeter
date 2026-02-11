package messaging

import "testing"

func TestIsPublicPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		expected bool
	}{
		{
			name:     "principal star compact",
			policy:   `{"Statement":[{"Principal":"*","Effect":"Allow"}]}`,
			expected: true,
		},
		{
			name:     "aws principal star compact",
			policy:   `{"Statement":[{"Principal":{"AWS":"*"},"Effect":"Allow"}]}`,
			expected: true,
		},
		{
			name:     "aws principal star spaced",
			policy:   `{"Statement":[{"Principal":{"AWS": "*"},"Effect":"Allow"}]}`,
			expected: true,
		},
		{
			name:     "non public principal",
			policy:   `{"Statement":[{"Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Effect":"Allow"}]}`,
			expected: false,
		},
		{
			name:     "empty policy",
			policy:   "",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isPublicPolicy(tc.policy)
			if got != tc.expected {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestExtractTopicName(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want string
	}{
		{
			name: "valid sns arn",
			arn:  "arn:aws:sns:us-east-1:123456789012:critical-alerts",
			want: "critical-alerts",
		},
		{
			name: "not an arn",
			arn:  "topic-name",
			want: "topic-name",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractTopicName(tc.arn)
			if got != tc.want {
				t.Fatalf("expected %s, got %s", tc.want, got)
			}
		})
	}
}
