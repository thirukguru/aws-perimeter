// Package ecrsecurity provides ECR security posture analysis.
package ecrsecurity

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// ECRRisk represents an ECR security finding.
type ECRRisk struct {
	RiskType       string
	Severity       string
	RepositoryName string
	RepositoryARN  string
	Description    string
	Recommendation string
}

// Service defines the ECR security interface.
type Service interface {
	GetECRSecurityRisks(ctx context.Context) ([]ECRRisk, error)
}

type service struct {
	ecrClient *ecr.Client
}

// NewService creates a new ECR security service.
func NewService(cfg aws.Config) Service {
	return &service{
		ecrClient: ecr.NewFromConfig(cfg),
	}
}

// GetECRSecurityRisks evaluates ECR repositories for common security issues.
func (s *service) GetECRSecurityRisks(ctx context.Context) ([]ECRRisk, error) {
	var risks []ECRRisk

	paginator := ecr.NewDescribeRepositoriesPaginator(s.ecrClient, &ecr.DescribeRepositoriesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// ECR may not be enabled or accessible in this account/region.
			break
		}

		for _, repo := range page.Repositories {
			name := aws.ToString(repo.RepositoryName)
			arn := aws.ToString(repo.RepositoryArn)

			if isMutableTagRepo(repo) {
				risks = append(risks, ECRRisk{
					RiskType:       "MutableImageTags",
					Severity:       SeverityHigh,
					RepositoryName: name,
					RepositoryARN:  arn,
					Description:    "Repository allows mutable image tags",
					Recommendation: "Set image tag mutability to IMMUTABLE to reduce supply-chain risk",
				})
			}

			if !scanOnPushEnabled(repo) {
				risks = append(risks, ECRRisk{
					RiskType:       "NoImageScanning",
					Severity:       SeverityHigh,
					RepositoryName: name,
					RepositoryARN:  arn,
					Description:    "ECR image scanning on push is disabled",
					Recommendation: "Enable scan on push to detect known vulnerabilities early",
				})
			}

			if !kmsEncryptionConfigured(repo) {
				risks = append(risks, ECRRisk{
					RiskType:       "UnencryptedECR",
					Severity:       SeverityMedium,
					RepositoryName: name,
					RepositoryARN:  arn,
					Description:    "Repository is not configured with KMS encryption",
					Recommendation: "Configure repository encryption type as KMS",
				})
			}

			hasLifecycle, err := s.hasLifecyclePolicy(ctx, name)
			if err == nil && !hasLifecycle {
				risks = append(risks, ECRRisk{
					RiskType:       "NoLifecyclePolicy",
					Severity:       SeverityMedium,
					RepositoryName: name,
					RepositoryARN:  arn,
					Description:    "Repository has no lifecycle policy configured",
					Recommendation: "Configure lifecycle policy to limit image retention",
				})
			}

			isPublic, err := s.isPublicRepository(ctx, name)
			if err == nil && isPublic {
				risks = append(risks, ECRRisk{
					RiskType:       "PublicECRRepository",
					Severity:       SeverityHigh,
					RepositoryName: name,
					RepositoryARN:  arn,
					Description:    "Repository policy allows public access",
					Recommendation: "Restrict repository policy principals and pull permissions",
				})
			}
		}
	}

	return risks, nil
}

func isMutableTagRepo(repo ecrtypes.Repository) bool {
	return repo.ImageTagMutability == ecrtypes.ImageTagMutabilityMutable
}

func scanOnPushEnabled(repo ecrtypes.Repository) bool {
	return repo.ImageScanningConfiguration != nil && repo.ImageScanningConfiguration.ScanOnPush
}

func kmsEncryptionConfigured(repo ecrtypes.Repository) bool {
	if repo.EncryptionConfiguration == nil {
		return false
	}
	return repo.EncryptionConfiguration.EncryptionType == ecrtypes.EncryptionTypeKms
}

func (s *service) hasLifecyclePolicy(ctx context.Context, repoName string) (bool, error) {
	_, err := s.ecrClient.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
		RepositoryName: aws.String(repoName),
	})
	if err == nil {
		return true, nil
	}
	if isLifecyclePolicyMissingError(err) {
		return false, nil
	}
	return false, err
}

func (s *service) isPublicRepository(ctx context.Context, repoName string) (bool, error) {
	out, err := s.ecrClient.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
		RepositoryName: aws.String(repoName),
	})
	if err != nil {
		if isRepositoryPolicyMissingError(err) {
			return false, nil
		}
		return false, err
	}
	return policyHasPublicPrincipal(aws.ToString(out.PolicyText)), nil
}

func isLifecyclePolicyMissingError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "lifecyclepolicynotfoundexception")
}

func isRepositoryPolicyMissingError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "repositorypolicynotfoundexception")
}

func policyHasPublicPrincipal(policyText string) bool {
	if strings.TrimSpace(policyText) == "" {
		return false
	}

	var policy struct {
		Statement []struct {
			Principal interface{} `json:"Principal"`
			Effect    string      `json:"Effect"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyText), &policy); err != nil {
		return false
	}

	for _, stmt := range policy.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}
		if principalContainsWildcard(stmt.Principal) {
			return true
		}
	}
	return false
}

func principalContainsWildcard(v interface{}) bool {
	switch p := v.(type) {
	case string:
		return strings.TrimSpace(p) == "*"
	case []interface{}:
		for _, item := range p {
			if principalContainsWildcard(item) {
				return true
			}
		}
	case map[string]interface{}:
		for _, inner := range p {
			if principalContainsWildcard(inner) {
				return true
			}
		}
	}
	return false
}
