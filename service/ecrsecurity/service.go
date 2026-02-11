// Package ecrsecurity provides ECR security posture analysis.
package ecrsecurity

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
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
	ecrClient       *ecr.Client
	inspectorClient *inspector2.Client
}

// NewService creates a new ECR security service.
func NewService(cfg aws.Config) Service {
	return &service{
		ecrClient:       ecr.NewFromConfig(cfg),
		inspectorClient: inspector2.NewFromConfig(cfg),
	}
}

// GetECRSecurityRisks evaluates ECR repositories for common security issues.
func (s *service) GetECRSecurityRisks(ctx context.Context) ([]ECRRisk, error) {
	var risks []ECRRisk
	suppressionKnown, suppressionAll, suppressionPatterns := s.getSuppressionPolicyCoverage(ctx)

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
				risks = append(risks, ECRRisk{
					RiskType:       "ImageTagImmutabilityBypass",
					Severity:       SeverityHigh,
					RepositoryName: name,
					RepositoryARN:  arn,
					Description:    "Tag immutability is disabled, allowing tags (including latest) to be overwritten",
					Recommendation: "Set image tag mutability to IMMUTABLE for release repositories and CI/CD-managed images",
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

			policyText, hasPolicy, err := s.getRepositoryPolicyText(ctx, name)
			if err == nil && hasPolicy {
				if policyHasPublicPrincipal(policyText) {
					risks = append(risks, ECRRisk{
						RiskType:       "PublicECRRepository",
						Severity:       SeverityHigh,
						RepositoryName: name,
						RepositoryARN:  arn,
						Description:    "Repository policy allows public access",
						Recommendation: "Restrict repository policy principals and pull permissions",
					})
				}

				if policyAllowsBatchGetImageFromWildcard(policyText) {
					risks = append(risks, ECRRisk{
						RiskType:       "CrossAccountPullPolicy",
						Severity:       SeverityCritical,
						RepositoryName: name,
						RepositoryARN:  arn,
						Description:    "Repository policy allows ecr:BatchGetImage pull access from wildcard principals",
						Recommendation: "Remove wildcard principals and explicitly scope pull access to approved account principals",
					})
				}

				repoAccountID := accountIDFromRepositoryARN(arn)
				externalAccounts := policyExternalBatchGetImageAccounts(policyText, repoAccountID)
				if len(externalAccounts) > 0 {
					risks = append(risks, ECRRisk{
						RiskType:       "CrossAccountPullPolicy",
						Severity:       SeverityHigh,
						RepositoryName: name,
						RepositoryARN:  arn,
						Description:    "Repository policy allows ecr:BatchGetImage pull access from external/unknown account principals",
						Recommendation: "Review and remove unapproved external account principals from repository pull permissions",
					})
				}
			}

			if suppressionKnown && !repoCoveredBySuppressionPolicy(name, suppressionAll, suppressionPatterns) {
				risks = append(risks, ECRRisk{
					RiskType:       "NoVulnerabilitySuppressionPolicy",
					Severity:       SeverityMedium,
					RepositoryName: name,
					RepositoryARN:  arn,
					Description:    "No vulnerability suppression/exception policy found for this repository",
					Recommendation: "Define an Inspector suppression filter policy with scoped repository criteria and expiry/governance controls",
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

func (s *service) getRepositoryPolicyText(ctx context.Context, repoName string) (string, bool, error) {
	out, err := s.ecrClient.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
		RepositoryName: aws.String(repoName),
	})
	if err != nil {
		if isRepositoryPolicyMissingError(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return aws.ToString(out.PolicyText), true, nil
}

func isLifecyclePolicyMissingError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "lifecyclepolicynotfoundexception")
}

func isRepositoryPolicyMissingError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "repositorypolicynotfoundexception")
}

func isAccessDeniedError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "accessdenied") || strings.Contains(msg, "unauthorized")
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

func policyAllowsBatchGetImageFromWildcard(policyText string) bool {
	statements := parsePolicyStatements(policyText)
	for _, stmt := range statements {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if !statementAllowsBatchGetImage(stmt.Action) {
			continue
		}
		_, wildcard := extractPrincipalAccountIDs(stmt.Principal)
		if wildcard {
			return true
		}
	}
	return false
}

func policyExternalBatchGetImageAccounts(policyText, repositoryAccountID string) []string {
	statements := parsePolicyStatements(policyText)
	seen := map[string]bool{}
	var external []string

	for _, stmt := range statements {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if !statementAllowsBatchGetImage(stmt.Action) {
			continue
		}
		accountIDs, wildcard := extractPrincipalAccountIDs(stmt.Principal)
		if wildcard {
			continue
		}
		for _, id := range accountIDs {
			if id == "" || id == repositoryAccountID || seen[id] {
				continue
			}
			seen[id] = true
			external = append(external, id)
		}
	}

	slices.Sort(external)
	return external
}

func parsePolicyStatements(policyText string) []struct {
	Principal interface{} `json:"Principal"`
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`
} {
	if strings.TrimSpace(policyText) == "" {
		return nil
	}
	var policy struct {
		Statement []struct {
			Principal interface{} `json:"Principal"`
			Effect    string      `json:"Effect"`
			Action    interface{} `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyText), &policy); err != nil {
		return nil
	}
	return policy.Statement
}

func statementAllowsBatchGetImage(action interface{}) bool {
	for _, a := range normalizeActionList(action) {
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "ecr:batchgetimage" || la == "ecr:*" || la == "*" {
			return true
		}
	}
	return false
}

func normalizeActionList(v interface{}) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []interface{}:
		out := make([]string, 0, len(a))
		for _, item := range a {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func extractPrincipalAccountIDs(principal interface{}) ([]string, bool) {
	accountIDs := []string{}
	seen := map[string]bool{}
	var wildcard bool

	var walk func(v interface{})
	walk = func(v interface{}) {
		switch p := v.(type) {
		case string:
			s := strings.TrimSpace(p)
			if s == "*" {
				wildcard = true
				return
			}
			if id, ok := extractAccountIDFromPrincipalString(s); ok && !seen[id] {
				seen[id] = true
				accountIDs = append(accountIDs, id)
			}
		case []interface{}:
			for _, item := range p {
				walk(item)
			}
		case map[string]interface{}:
			for _, inner := range p {
				walk(inner)
			}
		}
	}

	walk(principal)
	slices.Sort(accountIDs)
	return accountIDs, wildcard
}

var awsAccountIDPattern = regexp.MustCompile(`\b\d{12}\b`)

func extractAccountIDFromPrincipalString(s string) (string, bool) {
	if m := awsAccountIDPattern.FindString(s); m != "" {
		return m, true
	}
	return "", false
}

func accountIDFromRepositoryARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	if id, ok := extractAccountIDFromPrincipalString(parts[4]); ok {
		return id
	}
	return ""
}

func (s *service) getSuppressionPolicyCoverage(ctx context.Context) (known bool, all bool, repoPatterns []string) {
	paginator := inspector2.NewListFiltersPaginator(s.inspectorClient, &inspector2.ListFiltersInput{
		Action: inspectortypes.FilterActionSuppress,
	})

	seen := map[string]bool{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isAccessDeniedError(err) {
				return false, false, nil
			}
			return false, false, nil
		}
		known = true
		for _, filter := range page.Filters {
			if filter.Criteria == nil {
				all = true
				continue
			}
			criteria := filter.Criteria.EcrImageRepositoryName
			if len(criteria) == 0 {
				continue
			}
			for _, c := range criteria {
				v := strings.TrimSpace(aws.ToString(c.Value))
				if v == "" || seen[v] {
					continue
				}
				seen[v] = true
				repoPatterns = append(repoPatterns, v)
			}
		}
	}

	slices.Sort(repoPatterns)
	return known, all, repoPatterns
}

func repoCoveredBySuppressionPolicy(repoName string, all bool, patterns []string) bool {
	if all {
		return true
	}
	for _, p := range patterns {
		if repositoryPatternMatch(repoName, p) {
			return true
		}
	}
	return false
}

func repositoryPatternMatch(repoName, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(repoName, strings.TrimSuffix(pattern, "*"))
	}
	return repoName == pattern
}
