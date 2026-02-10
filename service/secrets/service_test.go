package secrets

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"
)

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip: %v", err)
	}
	return buf.Bytes()
}

func TestScanLambdaZipBytes_DetectsSecrets(t *testing.T) {
	zipData := makeZip(t, map[string]string{
		"index.js":     `const key="AKIA1234567890ABCDEF"`,
		"config/.env":  `DB_PASSWORD="supersecretvalue"`,
		"README.md":    `hello`,
		"assets/x.jpg": "binarydata",
	})

	findings := scanLambdaZipBytes("arn:aws:lambda:us-east-1:123:function:test", "test-fn", zipData)
	if len(findings) == 0 {
		t.Fatalf("expected findings from lambda zip scan")
	}
	for _, f := range findings {
		if f.ResourceType != "LambdaCode" {
			t.Fatalf("unexpected resource type: %s", f.ResourceType)
		}
		if f.ResourceName != "test-fn" {
			t.Fatalf("unexpected resource name: %s", f.ResourceName)
		}
		if f.Location == "" {
			t.Fatalf("expected location for finding")
		}
	}
}

func TestScanLambdaZipBytes_IgnoresNonTextCandidates(t *testing.T) {
	zipData := makeZip(t, map[string]string{
		"assets/data.bin": `AKIA1234567890ABCDEF`,
		"images/x.jpg":    `password="secret1234"`,
	})
	findings := scanLambdaZipBytes("arn", "fn", zipData)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-text candidate files, got %d", len(findings))
	}
}

func TestIsLambdaTextCandidate(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"main.go", true},
		{"config/.env", true},
		{"nested/credentials", true},
		{"assets/image.png", false},
	}
	for _, tt := range tests {
		if got := isLambdaTextCandidate(tt.path); got != tt.want {
			t.Fatalf("isLambdaTextCandidate(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestSeverityForSecretType(t *testing.T) {
	if got := severityForSecretType("GENERIC_SECRET"); got != SeverityHigh {
		t.Fatalf("expected GENERIC_SECRET to be %s, got %s", SeverityHigh, got)
	}
	if got := severityForSecretType("AWS_ACCESS_KEY"); got != SeverityCritical {
		t.Fatalf("expected AWS_ACCESS_KEY to be %s, got %s", SeverityCritical, got)
	}
}

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gzw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
	return gzBuf.Bytes()
}

func TestScanECRLayerBytes_DetectsSecrets(t *testing.T) {
	layer := makeTarGz(t, map[string]string{
		"app/.env":       `AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF`,
		"app/main":       "binary",
		"app/config.yml": "password: \"supersecretpass\"",
	})
	findings := scanECRLayerBytes("repo:latest", "sha256:abc", layer)
	if len(findings) == 0 {
		t.Fatalf("expected findings from ECR layer scan")
	}
	for _, f := range findings {
		if f.ResourceType != "ECRLayer" {
			t.Fatalf("unexpected resource type: %s", f.ResourceType)
		}
		if f.ResourceID != "repo:latest" {
			t.Fatalf("unexpected resource id: %s", f.ResourceID)
		}
	}
}

func TestScanECRLayerBytes_IgnoresNonTextFiles(t *testing.T) {
	layer := makeTarGz(t, map[string]string{
		"app/data.bin": `AKIA1234567890ABCDEF`,
		"app/img.jpg":  `password="secret"`,
	})
	findings := scanECRLayerBytes("repo:latest", "sha256:def", layer)
	if len(findings) != 0 {
		t.Fatalf("expected no findings from non-text ECR files, got %d", len(findings))
	}
}
