package model

import (
	"github.com/thirukguru/aws-perimeter/service/cloudtrail"
	"github.com/thirukguru/aws-perimeter/service/s3security"
	"github.com/thirukguru/aws-perimeter/service/secrets"
)

// RenderS3Input contains S3 security findings
type RenderS3Input struct {
	AccountID       string
	PublicBuckets   []s3security.BucketRisk
	UnencryptedBkts []s3security.BucketEncryption
	RiskyPolicies   []s3security.BucketPolicy
}

// RenderCloudTrailInput contains CloudTrail findings
type RenderCloudTrailInput struct {
	AccountID   string
	TrailStatus []cloudtrail.TrailStatus
	TrailGaps   []cloudtrail.TrailGap
}

// RenderSecretsInput contains secrets detection findings
type RenderSecretsInput struct {
	AccountID     string
	LambdaSecrets []secrets.SecretFinding
	EC2Secrets    []secrets.SecretFinding
	S3Secrets     []secrets.SecretFinding
}

// S3ReportJSON represents S3 JSON output
type S3ReportJSON struct {
	AccountID       string             `json:"account_id"`
	GeneratedAt     string             `json:"generated_at"`
	HasFindings     bool               `json:"has_findings"`
	PublicBuckets   []BucketRiskJSON   `json:"public_buckets"`
	UnencryptedBkts []BucketEncJSON    `json:"unencrypted_buckets"`
	RiskyPolicies   []BucketPolicyJSON `json:"risky_policies"`
}

// BucketRiskJSON for JSON output
type BucketRiskJSON struct {
	BucketName     string `json:"bucket_name"`
	RiskType       string `json:"risk_type"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// BucketEncJSON for JSON output
type BucketEncJSON struct {
	BucketName     string `json:"bucket_name"`
	IsEncrypted    bool   `json:"is_encrypted"`
	EncryptionType string `json:"encryption_type"`
	Severity       string `json:"severity"`
}

// BucketPolicyJSON for JSON output
type BucketPolicyJSON struct {
	BucketName      string   `json:"bucket_name"`
	AllowsPublic    bool     `json:"allows_public"`
	AllowsAnyAction bool     `json:"allows_any_action"`
	RiskyStatements []string `json:"risky_statements"`
	Severity        string   `json:"severity"`
}

// CloudTrailReportJSON for JSON output
type CloudTrailReportJSON struct {
	AccountID   string         `json:"account_id"`
	GeneratedAt string         `json:"generated_at"`
	HasFindings bool           `json:"has_findings"`
	Trails      []TrailJSON    `json:"trails"`
	Gaps        []TrailGapJSON `json:"gaps"`
}

// TrailJSON for JSON output
type TrailJSON struct {
	TrailName        string `json:"trail_name"`
	IsMultiRegion    bool   `json:"is_multi_region"`
	IsLogging        bool   `json:"is_logging"`
	HasLogValidation bool   `json:"has_log_validation"`
	Severity         string `json:"severity"`
}

// TrailGapJSON for JSON output
type TrailGapJSON struct {
	Issue          string `json:"issue"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// SecretsReportJSON for JSON output
type SecretsReportJSON struct {
	AccountID   string       `json:"account_id"`
	GeneratedAt string       `json:"generated_at"`
	HasFindings bool         `json:"has_findings"`
	TotalCount  int          `json:"total_count"`
	Secrets     []SecretJSON `json:"secrets"`
}

// SecretJSON for JSON output
type SecretJSON struct {
	ResourceType   string `json:"resource_type"`
	ResourceID     string `json:"resource_id"`
	ResourceName   string `json:"resource_name"`
	SecretType     string `json:"secret_type"`
	Location       string `json:"location"`
	Severity       string `json:"severity"`
	Recommendation string `json:"recommendation"`
}
