// Package governance provides SCP, tagging, and compliance security analysis.
package governance

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// OrganizationStatus represents AWS Organizations configuration
type OrganizationStatus struct {
	IsEnabled      bool
	FeatureSet     string
	AccountCount   int
	PolicyCount    int
	Severity       string
	Description    string
	Recommendation string
}

// SCPRisk represents SCP policy issues
type SCPRisk struct {
	PolicyID       string
	PolicyName     string
	AttachedTo     int
	HasDenyActions bool
	Severity       string
	Description    string
	Recommendation string
}

// OrgGuardrailRisk represents organization-wide SCP guardrail gaps.
type OrgGuardrailRisk struct {
	RiskType       string
	Severity       string
	Resource       string
	Description    string
	Recommendation string
}

// TaggingCompliance represents resource tagging compliance
type TaggingCompliance struct {
	TotalResources    int
	TaggedResources   int
	UntaggedResources int
	ComplianceRate    float64
	Severity          string
	Description       string
	Recommendation    string
}

// UntaggedResource represents a resource missing required tags
type UntaggedResource struct {
	ResourceARN  string
	ResourceType string
	MissingTags  []string
	Severity     string
	Description  string
}

type service struct {
	orgClient *organizations.Client
	tagClient *resourcegroupstaggingapi.Client
}

// Service is the interface for governance security analysis
type Service interface {
	GetOrganizationStatus(ctx context.Context) (*OrganizationStatus, error)
	GetSCPRisks(ctx context.Context) ([]SCPRisk, error)
	GetOrgSCPExpansionRisks(ctx context.Context) ([]OrgGuardrailRisk, error)
	GetTaggingCompliance(ctx context.Context, requiredTags []string) (*TaggingCompliance, error)
	GetUntaggedResources(ctx context.Context, requiredTags []string) ([]UntaggedResource, error)
}

// NewService creates a new governance service
func NewService(cfg aws.Config) Service {
	return &service{
		orgClient: organizations.NewFromConfig(cfg),
		tagClient: resourcegroupstaggingapi.NewFromConfig(cfg),
	}
}

// GetOrganizationStatus checks AWS Organizations configuration
func (s *service) GetOrganizationStatus(ctx context.Context) (*OrganizationStatus, error) {
	status := &OrganizationStatus{}

	org, err := s.orgClient.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		status.IsEnabled = false
		status.Severity = SeverityMedium
		status.Description = "AWS Organizations not enabled"
		status.Recommendation = "Consider using AWS Organizations for multi-account governance"
		return status, nil
	}

	status.IsEnabled = true
	status.FeatureSet = string(org.Organization.FeatureSet)

	// Count accounts
	accounts, _ := s.orgClient.ListAccounts(ctx, &organizations.ListAccountsInput{})
	if accounts != nil {
		status.AccountCount = len(accounts.Accounts)
	}

	// Count policies
	policies, _ := s.orgClient.ListPolicies(ctx, &organizations.ListPoliciesInput{
		Filter: orgtypes.PolicyTypeServiceControlPolicy,
	})
	if policies != nil {
		status.PolicyCount = len(policies.Policies)
	}

	if status.FeatureSet != "ALL" {
		status.Severity = SeverityMedium
		status.Description = "Organizations using consolidated billing only"
		status.Recommendation = "Enable all features for SCPs and policy-based governance"
	} else if status.PolicyCount == 0 {
		status.Severity = SeverityMedium
		status.Description = "No SCPs configured"
		status.Recommendation = "Create SCPs to enforce security guardrails"
	} else {
		status.Severity = SeverityLow
		status.Description = fmt.Sprintf("Organizations enabled with %d accounts and %d SCPs", status.AccountCount, status.PolicyCount)
		status.Recommendation = "Continue maintaining organizational governance"
	}

	return status, nil
}

// GetSCPRisks analyzes SCPs for potential issues
func (s *service) GetSCPRisks(ctx context.Context) ([]SCPRisk, error) {
	var risks []SCPRisk

	policies, err := s.orgClient.ListPolicies(ctx, &organizations.ListPoliciesInput{
		Filter: orgtypes.PolicyTypeServiceControlPolicy,
	})
	if err != nil {
		return risks, nil // Organizations not enabled
	}

	for _, policy := range policies.Policies {
		policyDetail, err := s.orgClient.DescribePolicy(ctx, &organizations.DescribePolicyInput{
			PolicyId: policy.Id,
		})
		if err != nil {
			continue
		}

		// Analyze policy content
		content := aws.ToString(policyDetail.Policy.Content)
		hasDeny := strings.Contains(content, "\"Effect\":\"Deny\"") ||
			strings.Contains(content, "\"Effect\": \"Deny\"")

		// Count attachments
		targets, _ := s.orgClient.ListTargetsForPolicy(ctx, &organizations.ListTargetsForPolicyInput{
			PolicyId: policy.Id,
		})
		attachedTo := 0
		if targets != nil {
			attachedTo = len(targets.Targets)
		}

		severity := SeverityLow
		description := "SCP properly configured"

		// Check for overly permissive SCPs
		if strings.Contains(content, "\"Action\":\"*\"") && strings.Contains(content, "\"Effect\":\"Allow\"") {
			severity = SeverityMedium
			description = "SCP allows all actions - may be too permissive"
		}

		// SCPs with no targets are unused
		if attachedTo == 0 {
			severity = SeverityLow
			description = "SCP not attached to any targets"
		}

		if severity != SeverityLow || attachedTo == 0 {
			risks = append(risks, SCPRisk{
				PolicyID:       aws.ToString(policy.Id),
				PolicyName:     aws.ToString(policy.Name),
				AttachedTo:     attachedTo,
				HasDenyActions: hasDeny,
				Severity:       severity,
				Description:    description,
				Recommendation: "Review SCP permissions and attachments",
			})
		}
	}

	return risks, nil
}

// GetOrgSCPExpansionRisks checks for core Organizations/SCP guardrail gaps.
func (s *service) GetOrgSCPExpansionRisks(ctx context.Context) ([]OrgGuardrailRisk, error) {
	var risks []OrgGuardrailRisk

	policies, err := s.orgClient.ListPolicies(ctx, &organizations.ListPoliciesInput{
		Filter: orgtypes.PolicyTypeServiceControlPolicy,
	})
	if err != nil {
		// Organizations not enabled or not accessible from this account.
		return risks, nil
	}

	hasSCPAttachedToRoot := false
	hasRootAccessBlock := false
	hasRegionRestriction := false
	hasAIServiceRestriction := false

	for _, policy := range policies.Policies {
		policyID := aws.ToString(policy.Id)
		if strings.TrimSpace(policyID) == "" {
			continue
		}

		detail, err := s.orgClient.DescribePolicy(ctx, &organizations.DescribePolicyInput{
			PolicyId: policy.Id,
		})
		if err != nil || detail.Policy == nil {
			continue
		}
		content := aws.ToString(detail.Policy.Content)

		if containsDenyRegionGuardrail(content) {
			hasRegionRestriction = true
		}
		if containsDenyRootAccess(content) {
			hasRootAccessBlock = true
		}
		if containsDenyService(content, "bedrock:") || containsDenyService(content, "sagemaker:") {
			hasAIServiceRestriction = true
		}

		targets, err := s.orgClient.ListTargetsForPolicy(ctx, &organizations.ListTargetsForPolicyInput{
			PolicyId: policy.Id,
		})
		if err != nil {
			continue
		}
		for _, t := range targets.Targets {
			if t.Type == orgtypes.TargetTypeRoot {
				hasSCPAttachedToRoot = true
				break
			}
		}
	}

	if !hasSCPAttachedToRoot {
		risks = append(risks, OrgGuardrailRisk{
			RiskType:       "NoSCPProtectionRootAccount",
			Severity:       SeverityHigh,
			Resource:       "Organizations Root",
			Description:    "No SCP is attached at the organization root",
			Recommendation: "Attach baseline SCP guardrails at root to protect all member accounts",
		})
	}

	if !hasRootAccessBlock {
		risks = append(risks, OrgGuardrailRisk{
			RiskType:       "MemberAccountRootAccessNotBlocked",
			Severity:       SeverityHigh,
			Resource:       "Organizations SCPs",
			Description:    "No SCP pattern detected to restrict root-user actions in member accounts",
			Recommendation: "Add SCP deny guardrails for root-user sensitive actions",
		})
	}

	if !hasRegionRestriction {
		risks = append(risks, OrgGuardrailRisk{
			RiskType:       "NoRegionRestrictionGuardrails",
			Severity:       SeverityMedium,
			Resource:       "Organizations SCPs",
			Description:    "No region restriction condition detected in SCPs",
			Recommendation: "Add SCP rules using aws:RequestedRegion to limit unauthorized regions",
		})
	}

	if !hasAIServiceRestriction {
		risks = append(risks, OrgGuardrailRisk{
			RiskType:       "AIServiceUnrestricted",
			Severity:       SeverityMedium,
			Resource:       "Organizations SCPs",
			Description:    "No SCP restrictions detected for Bedrock/SageMaker service usage",
			Recommendation: "Add SCP guardrails to restrict Bedrock/SageMaker usage to approved accounts/regions",
		})
	}

	return risks, nil
}

// GetTaggingCompliance checks resource tagging compliance
func (s *service) GetTaggingCompliance(ctx context.Context, requiredTags []string) (*TaggingCompliance, error) {
	compliance := &TaggingCompliance{}

	paginator := resourcegroupstaggingapi.NewGetResourcesPaginator(s.tagClient, &resourcegroupstaggingapi.GetResourcesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, resource := range page.ResourceTagMappingList {
			compliance.TotalResources++

			// Check for required tags
			hasAllRequired := true
			for _, reqTag := range requiredTags {
				found := false
				for _, tag := range resource.Tags {
					if aws.ToString(tag.Key) == reqTag {
						found = true
						break
					}
				}
				if !found {
					hasAllRequired = false
					break
				}
			}

			if hasAllRequired {
				compliance.TaggedResources++
			} else {
				compliance.UntaggedResources++
			}
		}
	}

	if compliance.TotalResources > 0 {
		compliance.ComplianceRate = float64(compliance.TaggedResources) / float64(compliance.TotalResources) * 100
	}

	if compliance.ComplianceRate < 50 {
		compliance.Severity = SeverityHigh
		compliance.Description = fmt.Sprintf("Only %.1f%% tagging compliance", compliance.ComplianceRate)
		compliance.Recommendation = "Implement tagging policies and remediate untagged resources"
	} else if compliance.ComplianceRate < 80 {
		compliance.Severity = SeverityMedium
		compliance.Description = fmt.Sprintf("%.1f%% tagging compliance", compliance.ComplianceRate)
		compliance.Recommendation = "Continue improving tagging coverage"
	} else {
		compliance.Severity = SeverityLow
		compliance.Description = fmt.Sprintf("%.1f%% tagging compliance", compliance.ComplianceRate)
		compliance.Recommendation = "Maintain tagging standards"
	}

	return compliance, nil
}

// GetUntaggedResources finds resources missing required tags
func (s *service) GetUntaggedResources(ctx context.Context, requiredTags []string) ([]UntaggedResource, error) {
	var untagged []UntaggedResource

	paginator := resourcegroupstaggingapi.NewGetResourcesPaginator(s.tagClient, &resourcegroupstaggingapi.GetResourcesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, resource := range page.ResourceTagMappingList {
			var missingTags []string

			for _, reqTag := range requiredTags {
				found := false
				for _, tag := range resource.Tags {
					if aws.ToString(tag.Key) == reqTag {
						found = true
						break
					}
				}
				if !found {
					missingTags = append(missingTags, reqTag)
				}
			}

			if len(missingTags) > 0 {
				resourceARN := aws.ToString(resource.ResourceARN)
				untagged = append(untagged, UntaggedResource{
					ResourceARN:  resourceARN,
					ResourceType: extractResourceType(resourceARN),
					MissingTags:  missingTags,
					Severity:     SeverityLow,
					Description:  fmt.Sprintf("Missing tags: %s", strings.Join(missingTags, ", ")),
				})
			}
		}
	}

	return untagged, nil
}

func extractResourceType(arn string) string {
	// ARN format: arn:aws:service:region:account:resource-type/resource-id
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 {
		return parts[2] + ":" + strings.Split(parts[5], "/")[0]
	}
	return "unknown"
}

func containsDenyRegionGuardrail(policyContent string) bool {
	lower := strings.ToLower(policyContent)
	return strings.Contains(lower, "\"effect\":\"deny\"") && strings.Contains(lower, "aws:requestedregion")
}

func containsDenyRootAccess(policyContent string) bool {
	lower := strings.ToLower(policyContent)
	if !strings.Contains(lower, "\"effect\":\"deny\"") {
		return false
	}
	return strings.Contains(lower, ":root") ||
		(strings.Contains(lower, "aws:principalarn") && strings.Contains(lower, "root")) ||
		(strings.Contains(lower, "aws:principaltype") && strings.Contains(lower, "root"))
}

func containsDenyService(policyContent, servicePrefix string) bool {
	lower := strings.ToLower(policyContent)
	return strings.Contains(lower, "\"effect\":\"deny\"") && strings.Contains(lower, strings.ToLower(servicePrefix))
}
