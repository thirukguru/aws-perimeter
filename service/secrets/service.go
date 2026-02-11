// Package secrets provides secrets detection in AWS resources.
package secrets

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
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

	// Lambda package scanning limits
	maxLambdaPackageSize = 10 * 1024 * 1024 // 10MB
	maxLambdaFiles       = 200
	maxLambdaFileSize    = 200 * 1024 // 200KB

	// ECR scanning limits
	maxECRRepositories = 20
	maxECRImages       = 5
	maxECRLayers       = 5
	maxECRLayerBytes   = 8 * 1024 * 1024 // 8MB
	maxECRFiles        = 200
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
	ecrClient    *ecr.Client
}

// Service is the interface for secrets detection
type Service interface {
	ScanLambdaEnvVars(ctx context.Context) ([]SecretFinding, error)
	ScanLambdaCodePackages(ctx context.Context) ([]SecretFinding, error)
	ScanEC2UserData(ctx context.Context) ([]SecretFinding, error)
	ScanPublicS3Objects(ctx context.Context) ([]SecretFinding, error)
	ScanECRImageLayers(ctx context.Context) ([]SecretFinding, error)
}

// NewService creates a new secrets detection service
func NewService(cfg aws.Config) Service {
	return &service{
		lambdaClient: lambda.NewFromConfig(cfg),
		ec2Client:    ec2.NewFromConfig(cfg),
		s3Client:     s3.NewFromConfig(cfg),
		ecrClient:    ecr.NewFromConfig(cfg),
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

// ScanLambdaCodePackages scans Lambda deployment ZIP contents for embedded secrets.
func (s *service) ScanLambdaCodePackages(ctx context.Context) ([]SecretFinding, error) {
	var findings []SecretFinding
	httpClient := &http.Client{Timeout: 20 * time.Second}

	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			fnName := aws.ToString(fn.FunctionName)
			fnArn := aws.ToString(fn.FunctionArn)

			out, err := s.lambdaClient.GetFunction(ctx, &lambda.GetFunctionInput{
				FunctionName: fn.FunctionName,
			})
			if err != nil || out == nil || out.Code == nil || out.Code.Location == nil {
				continue
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, aws.ToString(out.Code.Location), nil)
			if err != nil {
				continue
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				continue
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, maxLambdaPackageSize))
			_ = resp.Body.Close()
			if err != nil || len(data) == 0 {
				continue
			}

			findings = append(findings, scanLambdaZipBytes(fnArn, fnName, data)...)
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

func scanLambdaZipBytes(functionArn, functionName string, zipData []byte) []SecretFinding {
	findings := []SecretFinding{}
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return findings
	}

	filesScanned := 0
	for _, f := range zr.File {
		if filesScanned >= maxLambdaFiles {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}

		name := strings.ToLower(f.Name)
		if !isLambdaTextCandidate(name) {
			continue
		}
		filesScanned++

		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, maxLambdaFileSize))
		_ = rc.Close()
		if err != nil || len(content) == 0 {
			continue
		}
		contentStr := string(content)

		for secretType, pattern := range secretPatterns {
			if pattern.MatchString(contentStr) {
				findings = append(findings, SecretFinding{
					ResourceType:   "LambdaCode",
					ResourceID:     functionArn,
					ResourceName:   functionName,
					SecretType:     secretType,
					Location:       fmt.Sprintf("Lambda Package File: %s", f.Name),
					MatchedPattern: "[REDACTED - " + secretType + " detected]",
					Severity:       severityForSecretType(secretType),
					Recommendation: "Remove hardcoded secret from Lambda package and rotate exposed credentials",
				})
				break
			}
		}
	}
	return findings
}

type ecrManifest struct {
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

// ScanECRImageLayers scans ECR image layers for embedded secrets in text-like files.
func (s *service) ScanECRImageLayers(ctx context.Context) ([]SecretFinding, error) {
	findings := []SecretFinding{}
	httpClient := &http.Client{Timeout: 20 * time.Second}

	repoPaginator := ecr.NewDescribeRepositoriesPaginator(s.ecrClient, &ecr.DescribeRepositoriesInput{
		MaxResults: aws.Int32(maxECRRepositories),
	})

	for repoPaginator.HasMorePages() {
		repoPage, err := repoPaginator.NextPage(ctx)
		if err != nil {
			return findings, nil
		}
		for _, repo := range repoPage.Repositories {
			repoName := aws.ToString(repo.RepositoryName)
			if repoName == "" {
				continue
			}

			imagePaginator := ecr.NewDescribeImagesPaginator(s.ecrClient, &ecr.DescribeImagesInput{
				RepositoryName: aws.String(repoName),
				MaxResults:     aws.Int32(maxECRImages),
			})
			imageCount := 0
			for imagePaginator.HasMorePages() && imageCount < maxECRImages {
				imgPage, err := imagePaginator.NextPage(ctx)
				if err != nil {
					break
				}
				for _, imgDetail := range imgPage.ImageDetails {
					if imageCount >= maxECRImages {
						break
					}
					imageCount++
					if imgDetail.ImageDigest == nil {
						continue
					}

					imageID := ecrtypes.ImageIdentifier{ImageDigest: imgDetail.ImageDigest}
					imageRef := repoName + "@" + aws.ToString(imgDetail.ImageDigest)
					if len(imgDetail.ImageTags) > 0 && strings.TrimSpace(imgDetail.ImageTags[0]) != "" {
						tag := imgDetail.ImageTags[0]
						imageID.ImageTag = aws.String(tag)
						imageRef = repoName + ":" + tag
					}

					batchOut, err := s.ecrClient.BatchGetImage(ctx, &ecr.BatchGetImageInput{
						RepositoryName: aws.String(repoName),
						ImageIds:       []ecrtypes.ImageIdentifier{imageID},
						AcceptedMediaTypes: []string{
							"application/vnd.docker.distribution.manifest.v2+json",
							"application/vnd.oci.image.manifest.v1+json",
						},
					})
					if err != nil || len(batchOut.Images) == 0 || batchOut.Images[0].ImageManifest == nil {
						continue
					}

					var manifest ecrManifest
					if err := json.Unmarshal([]byte(aws.ToString(batchOut.Images[0].ImageManifest)), &manifest); err != nil {
						continue
					}

					layerCount := 0
					for _, layer := range manifest.Layers {
						if layerCount >= maxECRLayers || strings.TrimSpace(layer.Digest) == "" {
							break
						}
						layerCount++
						layerOut, err := s.ecrClient.GetDownloadUrlForLayer(ctx, &ecr.GetDownloadUrlForLayerInput{
							RepositoryName: aws.String(repoName),
							LayerDigest:    aws.String(layer.Digest),
						})
						if err != nil || layerOut.DownloadUrl == nil {
							continue
						}

						req, err := http.NewRequestWithContext(ctx, http.MethodGet, aws.ToString(layerOut.DownloadUrl), nil)
						if err != nil {
							continue
						}
						resp, err := httpClient.Do(req)
						if err != nil {
							continue
						}
						if resp.StatusCode != http.StatusOK {
							_ = resp.Body.Close()
							continue
						}
						layerBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxECRLayerBytes))
						_ = resp.Body.Close()
						if err != nil || len(layerBytes) == 0 {
							continue
						}
						findings = append(findings, scanECRLayerBytes(imageRef, layer.Digest, layerBytes)...)
					}
				}
			}
		}
	}
	return findings, nil
}

func scanECRLayerBytes(imageRef, layerDigest string, data []byte) []SecretFinding {
	findings := []SecretFinding{}
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return findings
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	filesScanned := 0
	for filesScanned < maxECRFiles {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr == nil || hdr.FileInfo().IsDir() {
			continue
		}
		name := strings.ToLower(hdr.Name)
		if !isLambdaTextCandidate(name) {
			continue
		}
		filesScanned++
		content, err := io.ReadAll(io.LimitReader(tr, maxLambdaFileSize))
		if err != nil || len(content) == 0 {
			continue
		}
		contentStr := string(content)
		for secretType, pattern := range secretPatterns {
			if pattern.MatchString(contentStr) {
				findings = append(findings, SecretFinding{
					ResourceType:   "ECRLayer",
					ResourceID:     imageRef,
					ResourceName:   imageRef,
					SecretType:     secretType,
					Location:       fmt.Sprintf("ECR Layer %s File: %s", layerDigest, hdr.Name),
					MatchedPattern: "[REDACTED - " + secretType + " detected]",
					Severity:       severityForSecretType(secretType),
					Recommendation: "Remove hardcoded secret from image layer, rebuild image, and rotate exposed credentials",
				})
				break
			}
		}
	}
	return findings
}

func isLambdaTextCandidate(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, allowed := range textFileExtensions {
		if ext == allowed {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(path))
	if strings.Contains(base, ".env") || strings.Contains(base, "credential") || strings.Contains(base, "config") {
		return true
	}
	return false
}

func severityForSecretType(secretType string) string {
	switch secretType {
	case "GENERIC_SECRET":
		return SeverityHigh
	default:
		return SeverityCritical
	}
}
