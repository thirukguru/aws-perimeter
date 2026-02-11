// Package iamadvanced provides advanced IAM security analysis.
package iamadvanced

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// RoleChainRisk represents a role chaining security issue
type RoleChainRisk struct {
	RoleName       string
	RoleARN        string
	ChainableRoles []string
	ChainDepth     int
	IsCircular     bool
	Severity       string
	Description    string
	Recommendation string
}

// ExternalIDRisk represents cross-account roles without external ID
type ExternalIDRisk struct {
	RoleName        string
	RoleARN         string
	TrustedAccount  string
	HasExternalID   bool
	ExternalIDValue string
	IsThirdParty    bool
	Severity        string
	Description     string
	Recommendation  string
}

// PermissionBoundaryRisk represents missing or weak permission boundaries
type PermissionBoundaryRisk struct {
	PrincipalType    string // "User" or "Role"
	PrincipalName    string
	PrincipalARN     string
	HasBoundary      bool
	BoundaryARN      string
	BoundaryIsStrict bool
	AttachedPolicies int
	Severity         string
	Description      string
	Recommendation   string
}

// InstanceProfileRisk represents EC2 instance profile issues
type InstanceProfileRisk struct {
	InstanceProfileName string
	InstanceProfileARN  string
	RoleName            string
	RoleARN             string
	HasOverlyPermissive bool
	AttachedPolicies    []string
	InUse               bool
	Severity            string
	Description         string
	Recommendation      string
}

// ServiceRoleMisuse represents service role configuration issues
type ServiceRoleMisuse struct {
	RoleName           string
	RoleARN            string
	ServicePrincipal   string
	IsOverlyPermissive bool
	AllowsPassRole     bool
	Severity           string
	Description        string
	Recommendation     string
}

type service struct {
	iamClient *iam.Client
	stsClient *sts.Client
	accountID string
}

// Service is the interface for advanced IAM security analysis
type Service interface {
	GetRoleChainRisks(ctx context.Context) ([]RoleChainRisk, error)
	GetExternalIDRisks(ctx context.Context) ([]ExternalIDRisk, error)
	GetPermissionBoundaryRisks(ctx context.Context) ([]PermissionBoundaryRisk, error)
	GetInstanceProfileRisks(ctx context.Context) ([]InstanceProfileRisk, error)
	GetServiceRoleMisuse(ctx context.Context) ([]ServiceRoleMisuse, error)
}

// NewService creates a new advanced IAM service
func NewService(cfg aws.Config) Service {
	return &service{
		iamClient: iam.NewFromConfig(cfg),
		stsClient: sts.NewFromConfig(cfg),
	}
}

func (s *service) getAccountID(ctx context.Context) string {
	if s.accountID == "" {
		identity, err := s.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err == nil {
			s.accountID = aws.ToString(identity.Account)
		}
	}
	return s.accountID
}

// GetRoleChainRisks analyzes role chaining depth and circular references
func (s *service) GetRoleChainRisks(ctx context.Context) ([]RoleChainRisk, error) {
	var risks []RoleChainRisk
	accountID := s.getAccountID(ctx)

	// Get all roles
	paginator := iam.NewListRolesPaginator(s.iamClient, &iam.ListRolesInput{})

	roleMap := make(map[string][]string) // role -> roles it can assume

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			roleName := aws.ToString(role.RoleName)

			// Parse trust policy to find what this role trusts
			trustDoc := aws.ToString(role.AssumeRolePolicyDocument)
			chainableRoles := extractChainableRoles(trustDoc, accountID)
			roleMap[roleName] = chainableRoles
		}
	}

	// Analyze chain depth for each role
	for roleName := range roleMap {
		depth, isCircular := analyzeChainDepth(roleName, roleMap, make(map[string]bool))

		if depth > 2 || isCircular {
			severity := SeverityMedium
			description := "Role chaining depth: " + string(rune('0'+depth))

			if isCircular {
				severity = SeverityHigh
				description = "Circular role chaining detected"
			} else if depth > 3 {
				severity = SeverityHigh
				description = "Excessive role chaining depth"
			}

			risks = append(risks, RoleChainRisk{
				RoleName:       roleName,
				ChainableRoles: roleMap[roleName],
				ChainDepth:     depth,
				IsCircular:     isCircular,
				Severity:       severity,
				Description:    description,
				Recommendation: "Limit role chaining to 2-3 hops maximum",
			})
		}
	}

	return risks, nil
}

// GetExternalIDRisks finds cross-account roles without external ID
func (s *service) GetExternalIDRisks(ctx context.Context) ([]ExternalIDRisk, error) {
	var risks []ExternalIDRisk
	accountID := s.getAccountID(ctx)

	paginator := iam.NewListRolesPaginator(s.iamClient, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			roleName := aws.ToString(role.RoleName)
			roleARN := aws.ToString(role.Arn)
			trustDoc := aws.ToString(role.AssumeRolePolicyDocument)

			// Parse trust policy
			var trustPolicy struct {
				Statement []struct {
					Principal interface{}                  `json:"Principal"`
					Condition map[string]map[string]string `json:"Condition"`
				} `json:"Statement"`
			}

			if err := json.Unmarshal([]byte(trustDoc), &trustPolicy); err != nil {
				continue
			}

			for _, stmt := range trustPolicy.Statement {
				// Check for cross-account trust
				trustedAccount := extractTrustedAccount(stmt.Principal)
				if trustedAccount == "" || trustedAccount == accountID || trustedAccount == "*" {
					continue
				}

				// Check for external ID
				hasExternalID := false
				externalIDValue := ""

				if stmt.Condition != nil {
					if stringEquals, ok := stmt.Condition["StringEquals"]; ok {
						if extID, ok := stringEquals["sts:ExternalId"]; ok {
							hasExternalID = true
							externalIDValue = extID
						}
					}
				}

				// Determine if third-party (not within same org)
				isThirdParty := !strings.HasPrefix(trustedAccount, accountID[:4]) // Simple heuristic

				severity := SeverityLow
				description := "Cross-account trust with external ID"

				if !hasExternalID {
					severity = SeverityHigh
					description = "Cross-account trust WITHOUT external ID - confused deputy risk"
				}

				if severity == SeverityHigh || (isThirdParty && !hasExternalID) {
					risks = append(risks, ExternalIDRisk{
						RoleName:        roleName,
						RoleARN:         roleARN,
						TrustedAccount:  trustedAccount,
						HasExternalID:   hasExternalID,
						ExternalIDValue: externalIDValue,
						IsThirdParty:    isThirdParty,
						Severity:        severity,
						Description:     description,
						Recommendation:  "Add sts:ExternalId condition for cross-account roles",
					})
				}
			}
		}
	}

	return risks, nil
}

// GetPermissionBoundaryRisks finds users/roles without permission boundaries
func (s *service) GetPermissionBoundaryRisks(ctx context.Context) ([]PermissionBoundaryRisk, error) {
	var risks []PermissionBoundaryRisk

	// Check users
	userPaginator := iam.NewListUsersPaginator(s.iamClient, &iam.ListUsersInput{})

	for userPaginator.HasMorePages() {
		page, err := userPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, user := range page.Users {
			userName := aws.ToString(user.UserName)
			userARN := aws.ToString(user.Arn)

			hasBoundary := user.PermissionsBoundary != nil
			boundaryARN := ""
			if hasBoundary {
				boundaryARN = aws.ToString(user.PermissionsBoundary.PermissionsBoundaryArn)
			}

			// Count attached policies
			policies, _ := s.iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
				UserName: aws.String(userName),
			})
			policyCount := 0
			if policies != nil {
				policyCount = len(policies.AttachedPolicies)
			}

			// Users with many policies but no boundary
			if !hasBoundary && policyCount > 2 {
				risks = append(risks, PermissionBoundaryRisk{
					PrincipalType:    "User",
					PrincipalName:    userName,
					PrincipalARN:     userARN,
					HasBoundary:      false,
					BoundaryARN:      boundaryARN,
					AttachedPolicies: policyCount,
					Severity:         SeverityMedium,
					Description:      "User has multiple policies without permission boundary",
					Recommendation:   "Apply permission boundary to limit maximum permissions",
				})
			}
		}
	}

	// Check roles
	rolePaginator := iam.NewListRolesPaginator(s.iamClient, &iam.ListRolesInput{})

	for rolePaginator.HasMorePages() {
		page, err := rolePaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			// Skip service-linked roles
			if strings.HasPrefix(aws.ToString(role.Path), "/aws-service-role/") {
				continue
			}

			roleName := aws.ToString(role.RoleName)
			roleARN := aws.ToString(role.Arn)

			hasBoundary := role.PermissionsBoundary != nil
			boundaryARN := ""
			if hasBoundary {
				boundaryARN = aws.ToString(role.PermissionsBoundary.PermissionsBoundaryArn)
			}

			// Count attached policies
			policies, _ := s.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: aws.String(roleName),
			})
			policyCount := 0
			if policies != nil {
				policyCount = len(policies.AttachedPolicies)
			}

			// Roles with admin-like policies but no boundary
			hasAdminPolicy := false
			if policies != nil {
				for _, pol := range policies.AttachedPolicies {
					policyName := aws.ToString(pol.PolicyName)
					if strings.Contains(policyName, "Admin") || strings.Contains(policyName, "FullAccess") {
						hasAdminPolicy = true
						break
					}
				}
			}

			if !hasBoundary && hasAdminPolicy {
				risks = append(risks, PermissionBoundaryRisk{
					PrincipalType:    "Role",
					PrincipalName:    roleName,
					PrincipalARN:     roleARN,
					HasBoundary:      false,
					BoundaryARN:      boundaryARN,
					AttachedPolicies: policyCount,
					Severity:         SeverityMedium,
					Description:      "Role has admin policies without permission boundary",
					Recommendation:   "Apply permission boundary to limit privilege escalation risk",
				})
			}
		}
	}

	return risks, nil
}

// GetInstanceProfileRisks finds EC2 instance profile issues
func (s *service) GetInstanceProfileRisks(ctx context.Context) ([]InstanceProfileRisk, error) {
	var risks []InstanceProfileRisk

	paginator := iam.NewListInstanceProfilesPaginator(s.iamClient, &iam.ListInstanceProfilesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// Return empty result on permission error instead of crashing scan
			return risks, nil
		}

		for _, profile := range page.InstanceProfiles {
			profileName := aws.ToString(profile.InstanceProfileName)
			profileARN := aws.ToString(profile.Arn)

			if len(profile.Roles) == 0 {
				continue
			}

			role := profile.Roles[0]
			roleName := aws.ToString(role.RoleName)
			roleARN := aws.ToString(role.Arn)

			// Check for overly permissive policies
			policies, _ := s.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: aws.String(roleName),
			})

			var policyNames []string
			isOverlyPermissive := false

			if policies != nil {
				for _, pol := range policies.AttachedPolicies {
					policyName := aws.ToString(pol.PolicyName)
					policyNames = append(policyNames, policyName)

					if strings.Contains(policyName, "AdministratorAccess") ||
						strings.Contains(policyName, "PowerUserAccess") ||
						policyName == "*" {
						isOverlyPermissive = true
					}
				}
			}

			if isOverlyPermissive {
				risks = append(risks, InstanceProfileRisk{
					InstanceProfileName: profileName,
					InstanceProfileARN:  profileARN,
					RoleName:            roleName,
					RoleARN:             roleARN,
					HasOverlyPermissive: true,
					AttachedPolicies:    policyNames,
					Severity:            SeverityHigh,
					Description:         "Instance profile has overly permissive policies",
					Recommendation:      "Apply least-privilege policies for EC2 workloads",
				})
			}
		}
	}

	return risks, nil
}

// GetServiceRoleMisuse finds service role configuration issues
func (s *service) GetServiceRoleMisuse(ctx context.Context) ([]ServiceRoleMisuse, error) {
	var risks []ServiceRoleMisuse

	paginator := iam.NewListRolesPaginator(s.iamClient, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			roleName := aws.ToString(role.RoleName)
			roleARN := aws.ToString(role.Arn)
			trustDoc := aws.ToString(role.AssumeRolePolicyDocument)

			// Check if it's a service role
			servicePrincipal := extractServicePrincipal(trustDoc)
			if servicePrincipal == "" {
				continue
			}

			// Check for iam:PassRole permission (can lead to privilege escalation)
			allowsPassRole := false
			isOverlyPermissive := false

			policies, _ := s.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: aws.String(roleName),
			})

			if policies != nil {
				for _, pol := range policies.AttachedPolicies {
					policyName := aws.ToString(pol.PolicyName)
					if strings.Contains(policyName, "Admin") || strings.Contains(policyName, "FullAccess") {
						isOverlyPermissive = true
					}

					// Check inline policies for iam:PassRole
					policyDoc, _ := s.iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
						RoleName:   aws.String(roleName),
						PolicyName: aws.String(policyName),
					})
					if policyDoc != nil {
						doc := aws.ToString(policyDoc.PolicyDocument)
						if strings.Contains(doc, "iam:PassRole") {
							allowsPassRole = true
						}
					}
				}
			}

			if isOverlyPermissive || allowsPassRole {
				severity := SeverityMedium
				description := "Service role configuration"

				if isOverlyPermissive && allowsPassRole {
					severity = SeverityHigh
					description = "Service role with admin access and PassRole - privilege escalation risk"
				} else if allowsPassRole {
					description = "Service role allows iam:PassRole"
				} else {
					description = "Service role has overly permissive policies"
				}

				risks = append(risks, ServiceRoleMisuse{
					RoleName:           roleName,
					RoleARN:            roleARN,
					ServicePrincipal:   servicePrincipal,
					IsOverlyPermissive: isOverlyPermissive,
					AllowsPassRole:     allowsPassRole,
					Severity:           severity,
					Description:        description,
					Recommendation:     "Apply least-privilege and restrict iam:PassRole",
				})
			}
		}
	}

	return risks, nil
}

// Helper functions
func extractChainableRoles(trustDoc, accountID string) []string {
	var roles []string

	var policy struct {
		Statement []struct {
			Principal interface{} `json:"Principal"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(trustDoc), &policy); err != nil {
		return roles
	}

	for _, stmt := range policy.Statement {
		principals := extractPrincipals(stmt.Principal)
		for _, p := range principals {
			if strings.Contains(p, ":role/") && strings.Contains(p, accountID) {
				roles = append(roles, p)
			}
		}
	}

	return roles
}

func extractPrincipals(principal interface{}) []string {
	var principals []string

	switch p := principal.(type) {
	case string:
		principals = append(principals, p)
	case map[string]interface{}:
		if aws, ok := p["AWS"]; ok {
			switch awsP := aws.(type) {
			case string:
				principals = append(principals, awsP)
			case []interface{}:
				for _, a := range awsP {
					if str, ok := a.(string); ok {
						principals = append(principals, str)
					}
				}
			}
		}
	}

	return principals
}

func analyzeChainDepth(roleName string, roleMap map[string][]string, visited map[string]bool) (int, bool) {
	if visited[roleName] {
		return 0, true // Circular
	}

	visited[roleName] = true
	defer func() { visited[roleName] = false }()

	maxDepth := 0
	isCircular := false

	for _, chainedRole := range roleMap[roleName] {
		// Extract role name from ARN
		parts := strings.Split(chainedRole, "/")
		chainedName := parts[len(parts)-1]

		if _, exists := roleMap[chainedName]; exists {
			depth, circular := analyzeChainDepth(chainedName, roleMap, visited)
			if circular {
				isCircular = true
			}
			if depth+1 > maxDepth {
				maxDepth = depth + 1
			}
		}
	}

	return maxDepth, isCircular
}

func extractTrustedAccount(principal interface{}) string {
	principals := extractPrincipals(principal)
	for _, p := range principals {
		if strings.Contains(p, "arn:aws:iam::") {
			parts := strings.Split(p, ":")
			if len(parts) >= 5 {
				return parts[4]
			}
		}
	}
	return ""
}

func extractServicePrincipal(trustDoc string) string {
	var policy struct {
		Statement []struct {
			Principal interface{} `json:"Principal"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(trustDoc), &policy); err != nil {
		return ""
	}

	for _, stmt := range policy.Statement {
		switch p := stmt.Principal.(type) {
		case map[string]interface{}:
			if svc, ok := p["Service"]; ok {
				switch s := svc.(type) {
				case string:
					return s
				case []interface{}:
					if len(s) > 0 {
						if str, ok := s[0].(string); ok {
							return str
						}
					}
				}
			}
		}
	}

	return ""
}
