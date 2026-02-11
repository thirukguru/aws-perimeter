// Package s3security provides S3 bucket security analysis.
package s3security

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// BucketRisk represents a security finding for an S3 bucket
type BucketRisk struct {
	BucketName        string
	RiskType          string
	Severity          string
	Description       string
	Recommendation    string
	PublicAccessBlock *PublicAccessBlockStatus
}

// PublicAccessBlockStatus indicates public access settings
type PublicAccessBlockStatus struct {
	BlockPublicAcls       bool
	IgnorePublicAcls      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
}

// BucketEncryption represents encryption status
type BucketEncryption struct {
	BucketName     string
	IsEncrypted    bool
	EncryptionType string // "SSE-S3", "SSE-KMS", "None"
	KMSKeyID       string
	Severity       string
	Recommendation string
}

// BucketPolicy represents a risky bucket policy
type BucketPolicy struct {
	BucketName      string
	AllowsPublic    bool
	AllowsAnyAction bool
	RiskyStatements []string
	Severity        string
	Recommendation  string
}

// SensitiveFileExposure represents exposed sensitive files in S3
type SensitiveFileExposure struct {
	BucketName     string
	FileName       string
	FileType       string // ".env", ".git", "credentials", etc.
	IsPublic       bool
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	client *s3.Client
}

// Service is the interface for S3 security analysis
type Service interface {
	GetPublicBuckets(ctx context.Context) ([]BucketRisk, error)
	GetUnencryptedBuckets(ctx context.Context) ([]BucketEncryption, error)
	GetRiskyBucketPolicies(ctx context.Context) ([]BucketPolicy, error)
	GetSensitiveFileExposures(ctx context.Context) ([]SensitiveFileExposure, error)
}

// NewService creates a new S3 security service
func NewService(cfg aws.Config) Service {
	return &service{
		client: s3.NewFromConfig(cfg),
	}
}

// GetPublicBuckets checks for buckets with public access
func (s *service) GetPublicBuckets(ctx context.Context) ([]BucketRisk, error) {
	var risks []BucketRisk

	buckets, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	for _, bucket := range buckets.Buckets {
		// Check public access block
		pab, err := s.client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})

		var publicAccessBlock *PublicAccessBlockStatus
		isPublicAccessBlocked := false

		if err == nil && pab.PublicAccessBlockConfiguration != nil {
			cfg := pab.PublicAccessBlockConfiguration
			publicAccessBlock = &PublicAccessBlockStatus{
				BlockPublicAcls:       aws.ToBool(cfg.BlockPublicAcls),
				IgnorePublicAcls:      aws.ToBool(cfg.IgnorePublicAcls),
				BlockPublicPolicy:     aws.ToBool(cfg.BlockPublicPolicy),
				RestrictPublicBuckets: aws.ToBool(cfg.RestrictPublicBuckets),
			}

			isPublicAccessBlocked = publicAccessBlock.BlockPublicAcls &&
				publicAccessBlock.IgnorePublicAcls &&
				publicAccessBlock.BlockPublicPolicy &&
				publicAccessBlock.RestrictPublicBuckets
		}

		// Check bucket ACL for public access
		acl, err := s.client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: bucket.Name,
		})

		hasPublicACL := false
		if err == nil {
			for _, grant := range acl.Grants {
				if grant.Grantee != nil && grant.Grantee.URI != nil {
					uri := *grant.Grantee.URI
					if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
						hasPublicACL = true
						break
					}
				}
			}
		}

		// Report findings
		if !isPublicAccessBlocked {
			severity := SeverityMedium
			if hasPublicACL {
				severity = SeverityCritical
			}

			risks = append(risks, BucketRisk{
				BucketName:        *bucket.Name,
				RiskType:          "PUBLIC_ACCESS_NOT_BLOCKED",
				Severity:          severity,
				Description:       "Public access block is not fully enabled",
				Recommendation:    "Enable all public access block settings",
				PublicAccessBlock: publicAccessBlock,
			})
		}

		if hasPublicACL {
			risks = append(risks, BucketRisk{
				BucketName:     *bucket.Name,
				RiskType:       "PUBLIC_ACL",
				Severity:       SeverityCritical,
				Description:    "Bucket has public ACL grants",
				Recommendation: "Remove public ACL grants and use bucket policies instead",
			})
		}
	}

	return risks, nil
}

// GetUnencryptedBuckets checks for buckets without default encryption
func (s *service) GetUnencryptedBuckets(ctx context.Context) ([]BucketEncryption, error) {
	var unencrypted []BucketEncryption

	buckets, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	for _, bucket := range buckets.Buckets {
		enc, err := s.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})

		if err != nil {
			// No encryption configured
			unencrypted = append(unencrypted, BucketEncryption{
				BucketName:     *bucket.Name,
				IsEncrypted:    false,
				EncryptionType: "None",
				Severity:       SeverityMedium,
				Recommendation: "Enable default encryption with SSE-S3 or SSE-KMS",
			})
			continue
		}

		if enc.ServerSideEncryptionConfiguration != nil {
			for _, rule := range enc.ServerSideEncryptionConfiguration.Rules {
				if rule.ApplyServerSideEncryptionByDefault != nil {
					algo := rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
					if algo == types.ServerSideEncryptionAes256 {
						// SSE-S3 is fine, skip
						continue
					}
					// KMS is also fine
				}
			}
		}
	}

	return unencrypted, nil
}

// GetRiskyBucketPolicies checks for overly permissive bucket policies
func (s *service) GetRiskyBucketPolicies(ctx context.Context) ([]BucketPolicy, error) {
	var risky []BucketPolicy

	buckets, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	for _, bucket := range buckets.Buckets {
		policy, err := s.client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		})

		if err != nil {
			continue // No policy is fine
		}

		if policy.Policy == nil {
			continue
		}

		// Parse policy
		var policyDoc struct {
			Statement []struct {
				Effect    string      `json:"Effect"`
				Principal interface{} `json:"Principal"`
				Action    interface{} `json:"Action"`
				Resource  interface{} `json:"Resource"`
			} `json:"Statement"`
		}

		if err := json.Unmarshal([]byte(*policy.Policy), &policyDoc); err != nil {
			continue
		}

		var riskyStmts []string
		allowsPublic := false
		allowsAnyAction := false

		for _, stmt := range policyDoc.Statement {
			if stmt.Effect != "Allow" {
				continue
			}

			// Check for public principal
			principalStr := principalToString(stmt.Principal)
			if principalStr == "*" || strings.Contains(principalStr, "*") {
				allowsPublic = true
				riskyStmts = append(riskyStmts, "Principal: * (public access)")
			}

			// Check for dangerous actions
			actions := normalizeToSlice(stmt.Action)
			for _, action := range actions {
				if action == "*" || action == "s3:*" {
					allowsAnyAction = true
					riskyStmts = append(riskyStmts, "Action: * (all actions allowed)")
				}
			}
		}

		if allowsPublic || allowsAnyAction {
			severity := SeverityHigh
			if allowsPublic && allowsAnyAction {
				severity = SeverityCritical
			}

			risky = append(risky, BucketPolicy{
				BucketName:      *bucket.Name,
				AllowsPublic:    allowsPublic,
				AllowsAnyAction: allowsAnyAction,
				RiskyStatements: riskyStmts,
				Severity:        severity,
				Recommendation:  "Review and restrict bucket policy",
			})
		}
	}

	return risky, nil
}

func principalToString(p interface{}) string {
	switch v := p.(type) {
	case string:
		return v
	case map[string]interface{}:
		if aws, ok := v["AWS"]; ok {
			return principalToString(aws)
		}
	}
	return ""
}

func normalizeToSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// Sensitive file patterns (EmeraldWhale campaign patterns)
var sensitiveFilePatterns = []struct {
	Pattern  string
	FileType string
	Severity string
}{
	{".env", "Environment File", SeverityCritical},
	{".git/", "Git Repository", SeverityCritical},
	{".git/config", "Git Config", SeverityCritical},
	{"credentials", "Credentials File", SeverityCritical},
	{".aws/credentials", "AWS Credentials", SeverityCritical},
	{".ssh/", "SSH Keys", SeverityCritical},
	{"id_rsa", "SSH Private Key", SeverityCritical},
	{".htpasswd", "HTTP Passwords", SeverityHigh},
	{"config.php", "PHP Config", SeverityHigh},
	{"wp-config.php", "WordPress Config", SeverityCritical},
	{".npmrc", "NPM Config", SeverityHigh},
	{".dockercfg", "Docker Config", SeverityHigh},
}

var sensitiveContentPatterns = []struct {
	Name     string
	Severity string
	Regex    *regexp.Regexp
}{
	{Name: "AWS Access Key", Severity: SeverityCritical, Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "AWS Secret Key", Severity: SeverityCritical, Regex: regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{20,}['"]?`)},
	{Name: "AWS Session Token", Severity: SeverityHigh, Regex: regexp.MustCompile(`(?i)aws[_-]?session[_-]?token\s*[:=]\s*['"]?[A-Za-z0-9/+=]{20,}['"]?`)},
	{Name: "Private Key Material", Severity: SeverityCritical, Regex: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{Name: "Generic Password Assignment", Severity: SeverityHigh, Regex: regexp.MustCompile(`(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{8,}['"]`)},
}

var likelyTextExtensions = []string{
	".env", ".txt", ".log", ".json", ".yaml", ".yml", ".ini", ".conf", ".cfg",
	".properties", ".sh", ".py", ".js", ".ts", ".go", ".java", ".php", ".xml", ".md",
}

// GetSensitiveFileExposures finds public buckets with exposed sensitive files
// Based on EmeraldWhale and ShinyHunters campaign patterns
func (s *service) GetSensitiveFileExposures(ctx context.Context) ([]SensitiveFileExposure, error) {
	var exposures []SensitiveFileExposure

	buckets, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)

		// Check if bucket is public first
		isPublic := s.isBucketPublic(ctx, bucketName)

		// List objects to find sensitive files (limit to 1000 for performance)
		objects, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  bucket.Name,
			MaxKeys: aws.Int32(1000),
		})
		if err != nil {
			continue
		}

		for _, obj := range objects.Contents {
			key := aws.ToString(obj.Key)
			keyLower := strings.ToLower(key)
			isPublicSeverityDowngrade := !isPublic

			matchedByName := false
			for _, pattern := range sensitiveFilePatterns {
				if strings.Contains(keyLower, strings.ToLower(pattern.Pattern)) {
					severity := pattern.Severity
					if isPublicSeverityDowngrade {
						severity = SeverityMedium // Lower severity if not public
					}

					exposures = append(exposures, SensitiveFileExposure{
						BucketName:     bucketName,
						FileName:       key,
						FileType:       pattern.FileType,
						IsPublic:       isPublic,
						Severity:       severity,
						Description:    pattern.FileType + " found in S3 bucket",
						Recommendation: "Remove sensitive file or block public access immediately",
					})
					matchedByName = true
					break // One match per file is enough
				}
			}
			if matchedByName {
				continue
			}

			if !isLikelyTextObject(keyLower, aws.ToInt64(obj.Size)) {
				continue
			}

			content, err := s.readObjectText(ctx, bucketName, key, 1024*1024)
			if err != nil || strings.TrimSpace(content) == "" {
				continue
			}

			indicatorName, indicatorSeverity, ok := detectSensitiveContent(content)
			if !ok {
				continue
			}
			if isPublicSeverityDowngrade {
				indicatorSeverity = SeverityMedium
			}
			exposures = append(exposures, SensitiveFileExposure{
				BucketName:     bucketName,
				FileName:       key,
				FileType:       indicatorName,
				IsPublic:       isPublic,
				Severity:       indicatorSeverity,
				Description:    indicatorName + " detected in object content",
				Recommendation: "Remove secrets from object content and rotate exposed credentials",
			})
		}
	}

	return exposures, nil
}

func (s *service) readObjectText(ctx context.Context, bucketName, key string, maxBytes int64) (string, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", err
	}
	defer out.Body.Close()

	data, err := io.ReadAll(io.LimitReader(out.Body, maxBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func isLikelyTextObject(key string, size int64) bool {
	if size <= 0 || size > 1024*1024 {
		return false
	}
	if strings.Contains(key, ".git/") || strings.HasSuffix(key, ".git") {
		return true
	}
	for _, ext := range likelyTextExtensions {
		if strings.HasSuffix(key, ext) {
			return true
		}
	}
	if strings.Contains(key, "credential") || strings.Contains(key, "secret") || strings.Contains(key, "config") {
		return true
	}
	return false
}

func detectSensitiveContent(content string) (name, severity string, ok bool) {
	for _, p := range sensitiveContentPatterns {
		if p.Regex.MatchString(content) {
			return p.Name, p.Severity, true
		}
	}
	return "", "", false
}

func (s *service) isBucketPublic(ctx context.Context, bucketName string) bool {
	// Check public access block
	pab, err := s.client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		// No public access block means potentially public
		return true
	}

	if pab.PublicAccessBlockConfiguration != nil {
		cfg := pab.PublicAccessBlockConfiguration
		allBlocked := aws.ToBool(cfg.BlockPublicAcls) &&
			aws.ToBool(cfg.IgnorePublicAcls) &&
			aws.ToBool(cfg.BlockPublicPolicy) &&
			aws.ToBool(cfg.RestrictPublicBuckets)
		if allBlocked {
			return false
		}
	}

	return true
}
