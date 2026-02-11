package s3security

import "testing"

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
