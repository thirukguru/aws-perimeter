// Package secrets provides secrets detection in AWS resources.
package secrets

import (
	"context"
	"encoding/base64"
	"io"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"

	// S3 scanning limits
	maxFileSizeToScan   = 100 * 1024 // 100KB max file size
	maxObjectsPerBucket = 100        // Limit objects per bucket
)

// SecretFinding represents a detected secret
type SecretFinding struct {
	ResourceType   string // "Lambda", "EC2UserData", "S3Object"
	ResourceID     string
	ResourceName   string
	SecretType     string // "AWS_ACCESS_KEY", "PASSWORD", "API_KEY", etc.
	Location       string // "Environment Variable", "User Data", etc.
	MatchedPattern string // Redacted match
	Severity       string
	Recommendation string
}

// Secret patterns to detect
var secretPatterns = map[string]*regexp.Regexp{
	"AWS_ACCESS_KEY":  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"AWS_SECRET_KEY":  regexp.MustCompile(`(?i)(aws_secret|secret_key|secretkey)['":\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
	"GENERIC_API_KEY": regexp.MustCompile(`(?i)(api[_-]?key|apikey)['":\s]*[=:]\s*['"]?([A-Za-z0-9_\-]{16,64})['"]?`),
	"GENERIC_SECRET":  regexp.MustCompile(`(?i)(secret|password|passwd|pwd)['":\s]*[=:]\s*['"]?([^\s'"]{8,})['"]?`),
	"PRIVATE_KEY":     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	"DATABASE_URL":    regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis)://[^\s]+:[^\s]+@`),
	"GITHUB_TOKEN":    regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
	"SLACK_TOKEN":     regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),
	"STRIPE_KEY":      regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	"GOOGLE_API_KEY":  regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
}

type service struct {
	lambdaClient *lambda.Client
	ec2Client    *ec2.Client
	s3Client     *s3.Client
}

// Service is the interface for secrets detection
type Service interface {
	ScanLambdaEnvVars(ctx context.Context) ([]SecretFinding, error)
	ScanEC2UserData(ctx context.Context) ([]SecretFinding, error)
	ScanPublicS3Objects(ctx context.Context) ([]SecretFinding, error)
}

// NewService creates a new secrets detection service
func NewService(cfg aws.Config) Service {
	return &service{
		lambdaClient: lambda.NewFromConfig(cfg),
		ec2Client:    ec2.NewFromConfig(cfg),
		s3Client:     s3.NewFromConfig(cfg),
	}
}

// ScanLambdaEnvVars scans Lambda functions for secrets in environment variables
func (s *service) ScanLambdaEnvVars(ctx context.Context) ([]SecretFinding, error) {
	var findings []SecretFinding

	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, fn := range page.Functions {
			// Get function configuration for environment variables
			config, err := s.lambdaClient.GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{
				FunctionName: fn.FunctionName,
			})
			if err != nil {
				continue
			}

			if config.Environment == nil || config.Environment.Variables == nil {
				continue
			}

			for key, value := range config.Environment.Variables {
				// Check for suspicious key names
				keyLower := strings.ToLower(key)
				if containsSecretKeyword(keyLower) {
					findings = append(findings, SecretFinding{
						ResourceType:   "Lambda",
						ResourceID:     aws.ToString(fn.FunctionArn),
						ResourceName:   aws.ToString(fn.FunctionName),
						SecretType:     "SUSPICIOUS_ENV_VAR",
						Location:       "Environment Variable: " + key,
						MatchedPattern: redactValue(value),
						Severity:       SeverityHigh,
						Recommendation: "Move secret to AWS Secrets Manager or Parameter Store",
					})
					continue
				}

				// Check value against secret patterns
				for secretType, pattern := range secretPatterns {
					if pattern.MatchString(value) {
						findings = append(findings, SecretFinding{
							ResourceType:   "Lambda",
							ResourceID:     aws.ToString(fn.FunctionArn),
							ResourceName:   aws.ToString(fn.FunctionName),
							SecretType:     secretType,
							Location:       "Environment Variable: " + key,
							MatchedPattern: redactValue(value),
							Severity:       SeverityCritical,
							Recommendation: "Move secret to AWS Secrets Manager and use IAM role",
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}

// ScanEC2UserData scans EC2 instances for secrets in user data
func (s *service) ScanEC2UserData(ctx context.Context) ([]SecretFinding, error) {
	var findings []SecretFinding

	paginator := ec2.NewDescribeInstancesPaginator(s.ec2Client, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				// Get instance user data
				userData, err := s.ec2Client.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
					InstanceId: instance.InstanceId,
					Attribute:  "userData",
				})
				if err != nil {
					continue
				}

				if userData.UserData == nil || userData.UserData.Value == nil {
					continue
				}

				// Decode base64 user data
				decoded, err := base64.StdEncoding.DecodeString(*userData.UserData.Value)
				if err != nil {
					continue
				}
				userDataStr := string(decoded)

				// Get instance name
				instanceName := aws.ToString(instance.InstanceId)
				for _, tag := range instance.Tags {
					if aws.ToString(tag.Key) == "Name" {
						instanceName = aws.ToString(tag.Value)
						break
					}
				}

				// Check for secrets in user data
				for secretType, pattern := range secretPatterns {
					if pattern.MatchString(userDataStr) {
						findings = append(findings, SecretFinding{
							ResourceType:   "EC2",
							ResourceID:     aws.ToString(instance.InstanceId),
							ResourceName:   instanceName,
							SecretType:     secretType,
							Location:       "User Data",
							MatchedPattern: "[REDACTED - " + secretType + " detected]",
							Severity:       SeverityCritical,
							Recommendation: "Remove secrets from user data, use IAM roles or Secrets Manager",
						})
						break // One finding per instance is enough
					}
				}
			}
		}
	}

	return findings, nil
}

func containsSecretKeyword(s string) bool {
	keywords := []string{"password", "secret", "api_key", "apikey", "token", "credential", "auth"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func redactValue(value string) string {
	if len(value) <= 8 {
		return "[REDACTED]"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

// Text file extensions to scan
var textFileExtensions = []string{
	".env", ".txt", ".json", ".yaml", ".yml", ".xml", ".ini",
	".cfg", ".conf", ".config", ".properties", ".sh", ".bash",
	".py", ".js", ".php", ".rb", ".go", ".java", ".sql", ".log",
	".pem", ".key", ".crt",
}

// ScanPublicS3Objects scans public S3 buckets for secrets in object contents
func (s *service) ScanPublicS3Objects(ctx context.Context) ([]SecretFinding, error) {
	var findings []SecretFinding

	buckets, err := s.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)

		// Check if bucket is public
		if !s.isBucketPublic(ctx, bucketName) {
			continue
		}

		// List objects (limited)
		objects, err := s.s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  bucket.Name,
			MaxKeys: aws.Int32(maxObjectsPerBucket),
		})
		if err != nil {
			continue
		}

		for _, obj := range objects.Contents {
			key := aws.ToString(obj.Key)
			size := aws.ToInt64(obj.Size)

			// Skip large files
			if size > maxFileSizeToScan || size == 0 {
				continue
			}

			// Only scan text-like files
			if !isTextFile(key) {
				continue
			}

			// Download and scan content
			contentFindings := s.scanS3ObjectContent(ctx, bucketName, key)
			findings = append(findings, contentFindings...)
		}
	}

	return findings, nil
}

func (s *service) isBucketPublic(ctx context.Context, bucketName string) bool {
	pab, err := s.s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		// No public access block = potentially public
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

func (s *service) scanS3ObjectContent(ctx context.Context, bucket, key string) []SecretFinding {
	var findings []SecretFinding

	obj, err := s.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return findings
	}
	defer obj.Body.Close()

	content, err := io.ReadAll(obj.Body)
	if err != nil {
		return findings
	}

	contentStr := string(content)

	for secretType, pattern := range secretPatterns {
		if pattern.MatchString(contentStr) {
			findings = append(findings, SecretFinding{
				ResourceType:   "S3Object",
				ResourceID:     "s3://" + bucket + "/" + key,
				ResourceName:   key,
				SecretType:     secretType,
				Location:       "Public S3 Bucket: " + bucket,
				MatchedPattern: "[REDACTED - " + secretType + " detected]",
				Severity:       SeverityCritical,
				Recommendation: "Remove secret from S3 object and rotate the exposed credential immediately",
			})
			break // One finding per object
		}
	}

	return findings
}

func isTextFile(key string) bool {
	keyLower := strings.ToLower(key)
	for _, ext := range textFileExtensions {
		if strings.HasSuffix(keyLower, ext) {
			return true
		}
	}
	// Also check for common sensitive file names
	baseName := keyLower
	if idx := strings.LastIndex(keyLower, "/"); idx >= 0 {
		baseName = keyLower[idx+1:]
	}
	sensitiveNames := []string{".env", "credentials", "config", ".htpasswd", ".npmrc", ".dockercfg"}
	for _, name := range sensitiveNames {
		if strings.Contains(baseName, name) {
			return true
		}
	}
	return false
}
