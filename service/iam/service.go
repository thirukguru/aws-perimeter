package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// Dangerous action patterns for privilege escalation detection
var privilegeEscalationActions = map[string]string{
	"iam:CreateAccessKey":         "Can create access keys for any user",
	"iam:CreateLoginProfile":      "Can create console password for any user",
	"iam:UpdateLoginProfile":      "Can update console password for any user",
	"iam:AttachUserPolicy":        "Can attach policies to users",
	"iam:AttachRolePolicy":        "Can attach policies to roles",
	"iam:AttachGroupPolicy":       "Can attach policies to groups",
	"iam:PutUserPolicy":           "Can add inline policies to users",
	"iam:PutRolePolicy":           "Can add inline policies to roles",
	"iam:PutGroupPolicy":          "Can add inline policies to groups",
	"iam:CreatePolicyVersion":     "Can create new policy versions",
	"iam:SetDefaultPolicyVersion": "Can set default policy version",
	"iam:UpdateAssumeRolePolicy":  "Can modify role trust policies",
	"iam:PassRole":                "Can pass roles to AWS services",
	"sts:AssumeRole":              "Can assume other roles",
	"lambda:CreateFunction":       "Can create Lambda with any role (with iam:PassRole)",
	"lambda:UpdateFunctionCode":   "Can update Lambda code",
	"ec2:RunInstances":            "Can launch EC2 with any role (with iam:PassRole)",
}

// GetPrivilegeEscalationRisks analyzes IAM for privilege escalation paths
func (s *service) GetPrivilegeEscalationRisks(ctx context.Context) ([]PrivEscRisk, error) {
	var risks []PrivEscRisk

	// Analyze users
	userRisks, err := s.analyzeUsersForPrivEsc(ctx)
	if err != nil {
		return nil, fmt.Errorf("analyzing users: %w", err)
	}
	risks = append(risks, userRisks...)

	// Analyze roles
	roleRisks, err := s.analyzeRolesForPrivEsc(ctx)
	if err != nil {
		return nil, fmt.Errorf("analyzing roles: %w", err)
	}
	risks = append(risks, roleRisks...)

	return risks, nil
}

func (s *service) analyzeUsersForPrivEsc(ctx context.Context) ([]PrivEscRisk, error) {
	var risks []PrivEscRisk

	paginator := iam.NewListUsersPaginator(s.client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, user := range page.Users {
			dangerousActions := s.getUserDangerousActions(ctx, *user.UserName)

			if len(dangerousActions) > 0 {
				risk := PrivEscRisk{
					PrincipalType:    "User",
					PrincipalName:    *user.UserName,
					PrincipalARN:     *user.Arn,
					DangerousActions: dangerousActions,
					Severity:         SeverityCritical,
					Recommendation:   "Review and restrict IAM permissions following least-privilege principle",
				}

				risk.EscalationPath = buildEscalationPath(dangerousActions)
				risks = append(risks, risk)
			}
		}
	}

	return risks, nil
}

func (s *service) analyzeRolesForPrivEsc(ctx context.Context) ([]PrivEscRisk, error) {
	var risks []PrivEscRisk

	paginator := iam.NewListRolesPaginator(s.client, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			// Skip AWS service-linked roles
			if strings.HasPrefix(*role.Path, "/aws-service-role/") {
				continue
			}

			dangerousActions := s.getRoleDangerousActions(ctx, *role.RoleName)

			if len(dangerousActions) > 0 {
				risk := PrivEscRisk{
					PrincipalType:    "Role",
					PrincipalName:    *role.RoleName,
					PrincipalARN:     *role.Arn,
					DangerousActions: dangerousActions,
					Severity:         SeverityHigh,
					Recommendation:   "Review role permissions and restrict to minimum required",
				}

				risk.EscalationPath = buildEscalationPath(dangerousActions)
				risks = append(risks, risk)
			}
		}
	}

	return risks, nil
}

func (s *service) getUserDangerousActions(ctx context.Context, userName string) []string {
	var dangerous []string

	// Check attached policies
	attachedPolicies, err := s.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(userName),
	})
	if err == nil {
		for _, policy := range attachedPolicies.AttachedPolicies {
			actions := s.getPolicyDangerousActions(ctx, *policy.PolicyArn)
			dangerous = append(dangerous, actions...)
		}
	}

	// Check inline policies
	inlinePolicies, err := s.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
		UserName: aws.String(userName),
	})
	if err == nil {
		for _, policyName := range inlinePolicies.PolicyNames {
			policyDoc, err := s.client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
				UserName:   aws.String(userName),
				PolicyName: aws.String(policyName),
			})
			if err == nil && policyDoc.PolicyDocument != nil {
				actions := extractDangerousActionsFromDoc(*policyDoc.PolicyDocument)
				dangerous = append(dangerous, actions...)
			}
		}
	}

	return uniqueStrings(dangerous)
}

func (s *service) getRoleDangerousActions(ctx context.Context, roleName string) []string {
	var dangerous []string

	// Check attached policies
	attachedPolicies, err := s.client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		for _, policy := range attachedPolicies.AttachedPolicies {
			actions := s.getPolicyDangerousActions(ctx, *policy.PolicyArn)
			dangerous = append(dangerous, actions...)
		}
	}

	// Check inline policies
	inlinePolicies, err := s.client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		for _, policyName := range inlinePolicies.PolicyNames {
			policyDoc, err := s.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err == nil && policyDoc.PolicyDocument != nil {
				actions := extractDangerousActionsFromDoc(*policyDoc.PolicyDocument)
				dangerous = append(dangerous, actions...)
			}
		}
	}

	return uniqueStrings(dangerous)
}

func (s *service) getPolicyDangerousActions(ctx context.Context, policyArn string) []string {
	policy, err := s.client.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return nil
	}

	version, err := s.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil || version.PolicyVersion.Document == nil {
		return nil
	}

	return extractDangerousActionsFromDoc(*version.PolicyVersion.Document)
}

func extractDangerousActionsFromDoc(encodedDoc string) []string {
	var dangerous []string

	decoded, err := url.QueryUnescape(encodedDoc)
	if err != nil {
		return nil
	}

	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		actions := normalizeStringOrSlice(stmt.Action)

		for _, action := range actions {
			// Check for wildcard admin
			if action == "*" || action == "*:*" {
				dangerous = append(dangerous, "*:* (Full Admin)")
				continue
			}

			// Check against known dangerous actions
			for dangerousAction := range privilegeEscalationActions {
				if actionMatches(action, dangerousAction) {
					dangerous = append(dangerous, dangerousAction)
				}
			}
		}
	}

	return dangerous
}

type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}

func normalizeStringOrSlice(v interface{}) []string {
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

func actionMatches(pattern, action string) bool {
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)

	if pattern == action {
		return true
	}

	// Handle wildcards like iam:*
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(action, prefix)
	}

	return false
}

func buildEscalationPath(actions []string) string {
	if containsAny(actions, "*:* (Full Admin)") {
		return "Full admin access allows complete privilege escalation"
	}

	var paths []string

	if containsAny(actions, "iam:CreateAccessKey") {
		paths = append(paths, "Create access keys for other users")
	}

	if containsAny(actions, "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy") {
		paths = append(paths, "Attach admin policy to self")
	}

	if containsAny(actions, "iam:PassRole") && containsAny(actions, "lambda:CreateFunction", "ec2:RunInstances") {
		paths = append(paths, "Pass high-privilege role to compute service")
	}

	if containsAny(actions, "iam:UpdateAssumeRolePolicy") {
		paths = append(paths, "Modify role trust policy to allow self")
	}

	if len(paths) == 0 {
		return "Multiple dangerous IAM permissions detected"
	}

	return strings.Join(paths, "; ")
}

func containsAny(slice []string, items ...string) bool {
	for _, s := range slice {
		for _, item := range items {
			if s == item {
				return true
			}
		}
	}
	return false
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// GetStaleCredentials finds credentials that haven't been used or rotated recently
func (s *service) GetStaleCredentials(ctx context.Context, maxAgeDays int) ([]StaleCredential, error) {
	var stale []StaleCredential

	paginator := iam.NewListUsersPaginator(s.client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, user := range page.Users {
			userStale, err := s.checkUserCredentials(ctx, *user.UserName, maxAgeDays)
			if err != nil {
				continue // Skip errors for individual users
			}

			stale = append(stale, userStale...)
		}
	}

	return stale, nil
}

func (s *service) checkUserCredentials(ctx context.Context, userName string, maxAgeDays int) ([]StaleCredential, error) {
	var stale []StaleCredential
	now := time.Now()

	// Check access keys
	keys, err := s.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return nil, err
	}

	for _, key := range keys.AccessKeyMetadata {
		if key.Status == types.StatusTypeInactive {
			continue
		}

		lastUsed, err := s.client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
			AccessKeyId: key.AccessKeyId,
		})

		var lastUsedDate string
		var daysSinceUse int

		if err == nil && lastUsed.AccessKeyLastUsed != nil && lastUsed.AccessKeyLastUsed.LastUsedDate != nil {
			lastUsedDate = lastUsed.AccessKeyLastUsed.LastUsedDate.Format("2006-01-02")
			daysSinceUse = int(now.Sub(*lastUsed.AccessKeyLastUsed.LastUsedDate).Hours() / 24)
		} else {
			lastUsedDate = "Never"
			daysSinceUse = int(now.Sub(*key.CreateDate).Hours() / 24)
		}

		daysSinceCreation := int(now.Sub(*key.CreateDate).Hours() / 24)

		if daysSinceCreation >= maxAgeDays || (lastUsedDate == "Never" && daysSinceCreation > 30) {
			severity := SeverityMedium
			if daysSinceCreation >= 180 {
				severity = SeverityHigh
			}

			stale = append(stale, StaleCredential{
				UserName:          userName,
				CredentialType:    "access_key",
				AccessKeyID:       *key.AccessKeyId,
				CreatedDate:       key.CreateDate.Format("2006-01-02"),
				LastUsedDate:      lastUsedDate,
				DaysSinceLastUse:  daysSinceUse,
				DaysSinceCreation: daysSinceCreation,
				Severity:          severity,
				Recommendation:    "Rotate or delete this access key",
			})
		}
	}

	return stale, nil
}

// GetCrossAccountTrusts analyzes role trust policies for cross-account access
func (s *service) GetCrossAccountTrusts(ctx context.Context, currentAccountID string) ([]CrossAccountTrust, error) {
	var trusts []CrossAccountTrust

	paginator := iam.NewListRolesPaginator(s.client, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			// Skip AWS service-linked roles
			if strings.HasPrefix(*role.Path, "/aws-service-role/") {
				continue
			}

			if role.AssumeRolePolicyDocument == nil {
				continue
			}

			decoded, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
			if err != nil {
				continue
			}

			var doc policyDocument
			if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
				continue
			}

			for _, stmt := range doc.Statement {
				if stmt.Effect != "Allow" {
					continue
				}

				principals := extractPrincipals(stmt)

				for _, principal := range principals {
					trust := analyzePrincipal(principal, *role.RoleName, *role.Arn, currentAccountID)
					if trust != nil {
						trusts = append(trusts, *trust)
					}
				}
			}
		}
	}

	return trusts, nil
}

func extractPrincipals(stmt policyStatement) []string {
	// This is simplified - real implementation would handle Principal field
	return nil
}

func analyzePrincipal(principal, roleName, roleArn, currentAccountID string) *CrossAccountTrust {
	// Extract account ID from principal ARN
	if strings.HasPrefix(principal, "arn:aws:iam::") {
		parts := strings.Split(principal, ":")
		if len(parts) >= 5 {
			accountID := parts[4]

			if accountID != currentAccountID && accountID != "" {
				return &CrossAccountTrust{
					RoleName:          roleName,
					RoleARN:           roleArn,
					TrustedAccountID:  accountID,
					TrustedPrincipal:  principal,
					IsExternalAccount: true,
					Severity:          SeverityHigh,
					Description:       fmt.Sprintf("Role can be assumed by account %s", accountID),
					Recommendation:    "Verify this cross-account trust is intentional and necessary",
				}
			}
		}
	}

	if principal == "*" {
		return &CrossAccountTrust{
			RoleName:           roleName,
			RoleARN:            roleArn,
			TrustedPrincipal:   "*",
			AllowsAnyPrincipal: true,
			Severity:           SeverityCritical,
			Description:        "Role can be assumed by ANY AWS principal",
			Recommendation:     "Immediately restrict trust policy - this is a critical security risk",
		}
	}

	return nil
}

// GetUsersWithoutMFA finds console users without MFA enabled
func (s *service) GetUsersWithoutMFA(ctx context.Context) ([]UserMFAStatus, error) {
	var noMFA []UserMFAStatus

	paginator := iam.NewListUsersPaginator(s.client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, user := range page.Users {
			// Check if user has console access (login profile)
			_, err := s.client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
				UserName: user.UserName,
			})

			hasConsole := err == nil

			if !hasConsole {
				continue // Skip users without console access
			}

			// Check MFA devices
			mfaDevices, err := s.client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
				UserName: user.UserName,
			})

			hasMFA := err == nil && len(mfaDevices.MFADevices) > 0

			if !hasMFA {
				noMFA = append(noMFA, UserMFAStatus{
					UserName:       *user.UserName,
					UserARN:        *user.Arn,
					HasConsolePwd:  true,
					MFAEnabled:     false,
					Severity:       SeverityMedium,
					Recommendation: "Enable MFA for this user",
				})
			}
		}
	}

	return noMFA, nil
}

// GetOverlyPermissivePolicies finds policies with dangerous permissions
func (s *service) GetOverlyPermissivePolicies(ctx context.Context) ([]DangerousPolicy, error) {
	var dangerous []DangerousPolicy

	paginator := iam.NewListPoliciesPaginator(s.client, &iam.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal, // Only customer-managed policies
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, policy := range page.Policies {
			if policy.AttachmentCount == nil || *policy.AttachmentCount == 0 {
				continue // Skip unattached policies
			}

			dangerousStmts := s.analyzePolicyForDanger(ctx, *policy.Arn, policy.DefaultVersionId)

			if len(dangerousStmts) > 0 {
				dangerous = append(dangerous, DangerousPolicy{
					PolicyName:     *policy.PolicyName,
					PolicyARN:      *policy.Arn,
					PolicyType:     "Customer Managed",
					DangerousStmts: dangerousStmts,
					Severity:       SeverityCritical,
					Recommendation: "Review and restrict policy permissions",
				})
			}
		}
	}

	return dangerous, nil
}

func (s *service) analyzePolicyForDanger(ctx context.Context, policyArn string, versionId *string) []DangerousStatement {
	var dangerous []DangerousStatement

	version, err := s.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: versionId,
	})
	if err != nil || version.PolicyVersion.Document == nil {
		return nil
	}

	decoded, err := url.QueryUnescape(*version.PolicyVersion.Document)
	if err != nil {
		return nil
	}

	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		actions := normalizeStringOrSlice(stmt.Action)
		resources := normalizeStringOrSlice(stmt.Resource)

		// Check for full admin
		for _, action := range actions {
			if action == "*" || action == "*:*" {
				for _, resource := range resources {
					if resource == "*" {
						dangerous = append(dangerous, DangerousStatement{
							Effect:    "Allow",
							Actions:   actions,
							Resources: resources,
							Reason:    "Full admin access (Action: *, Resource: *)",
						})
					}
				}
			}
		}
	}

	return dangerous
}

// GetMissingBoundaries finds IAM users/roles that have high privileges without permission boundaries
func (s *service) GetMissingBoundaries(ctx context.Context) ([]PermissionBoundary, error) {
	var missing []PermissionBoundary

	// Check roles for missing boundaries
	rolePaginator := iam.NewListRolesPaginator(s.client, &iam.ListRolesInput{})

	for rolePaginator.HasMorePages() {
		page, err := rolePaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			// Skip AWS service-linked roles
			if strings.HasPrefix(*role.Path, "/aws-service-role/") {
				continue
			}

			hasBoundary := role.PermissionsBoundary != nil
			boundaryARN := ""
			if hasBoundary {
				boundaryARN = aws.ToString(role.PermissionsBoundary.PermissionsBoundaryArn)
			}

			// Check if role has admin-level permissions
			isAdmin := s.hasAdminPermissions(ctx, *role.RoleName, "role")

			// Only report high-privilege roles without boundaries
			if isAdmin && !hasBoundary {
				missing = append(missing, PermissionBoundary{
					PrincipalType:  "Role",
					PrincipalName:  *role.RoleName,
					PrincipalARN:   *role.Arn,
					HasBoundary:    hasBoundary,
					BoundaryARN:    boundaryARN,
					IsAdmin:        isAdmin,
					Severity:       SeverityHigh,
					Recommendation: "Add permission boundary to limit maximum permissions",
				})
			}
		}
	}

	// Check users for missing boundaries
	userPaginator := iam.NewListUsersPaginator(s.client, &iam.ListUsersInput{})

	for userPaginator.HasMorePages() {
		page, err := userPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, user := range page.Users {
			hasBoundary := user.PermissionsBoundary != nil
			boundaryARN := ""
			if hasBoundary {
				boundaryARN = aws.ToString(user.PermissionsBoundary.PermissionsBoundaryArn)
			}

			// Check if user has admin-level permissions
			isAdmin := s.hasAdminPermissions(ctx, *user.UserName, "user")

			// Only report high-privilege users without boundaries
			if isAdmin && !hasBoundary {
				missing = append(missing, PermissionBoundary{
					PrincipalType:  "User",
					PrincipalName:  *user.UserName,
					PrincipalARN:   *user.Arn,
					HasBoundary:    hasBoundary,
					BoundaryARN:    boundaryARN,
					IsAdmin:        isAdmin,
					Severity:       SeverityMedium,
					Recommendation: "Add permission boundary to limit maximum permissions",
				})
			}
		}
	}

	return missing, nil
}

func (s *service) hasAdminPermissions(ctx context.Context, name, principalType string) bool {
	var policyArns []string

	if principalType == "role" {
		attached, err := s.client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(name),
		})
		if err == nil {
			for _, p := range attached.AttachedPolicies {
				policyArns = append(policyArns, *p.PolicyArn)
			}
		}
	} else {
		attached, err := s.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(name),
		})
		if err == nil {
			for _, p := range attached.AttachedPolicies {
				policyArns = append(policyArns, *p.PolicyArn)
			}
		}
	}

	// Check for AdministratorAccess or similar
	for _, arn := range policyArns {
		if strings.Contains(arn, "AdministratorAccess") ||
			strings.Contains(arn, "PowerUserAccess") ||
			strings.Contains(arn, "IAMFullAccess") {
			return true
		}
	}

	return false
}

// GetUnusedAdminRoles finds admin roles that haven't been used recently
// Based on threat intel - unused admin roles are targets for credential abuse
func (s *service) GetUnusedAdminRoles(ctx context.Context, maxAgeDays int) ([]UnusedAdminRole, error) {
	var unused []UnusedAdminRole

	paginator := iam.NewListRolesPaginator(s.client, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range page.Roles {
			// Skip AWS service-linked roles
			if strings.HasPrefix(*role.Path, "/aws-service-role/") {
				continue
			}

			// Check if role has admin permissions
			if !s.hasAdminPermissions(ctx, *role.RoleName, "role") {
				continue
			}

			// Get role last used info
			roleInfo, err := s.client.GetRole(ctx, &iam.GetRoleInput{
				RoleName: role.RoleName,
			})
			if err != nil {
				continue
			}

			var lastUsedDate string
			var daysSinceUse int

			if roleInfo.Role.RoleLastUsed != nil && roleInfo.Role.RoleLastUsed.LastUsedDate != nil {
				lastUsedDate = roleInfo.Role.RoleLastUsed.LastUsedDate.Format("2006-01-02")
				daysSinceUse = int(time.Now().Sub(*roleInfo.Role.RoleLastUsed.LastUsedDate).Hours() / 24)
			} else {
				lastUsedDate = "Never"
				daysSinceUse = int(time.Now().Sub(*role.CreateDate).Hours() / 24)
			}

			if daysSinceUse >= maxAgeDays {
				severity := SeverityMedium
				if daysSinceUse >= 180 {
					severity = SeverityHigh
				}

				unused = append(unused, UnusedAdminRole{
					RoleName:       *role.RoleName,
					RoleARN:        *role.Arn,
					LastUsedDate:   lastUsedDate,
					DaysSinceUse:   daysSinceUse,
					HasAdminAccess: true,
					Severity:       severity,
					Description:    fmt.Sprintf("Admin role unused for %d days - potential compromise target", daysSinceUse),
					Recommendation: "Review if role is needed, delete if unused, or rotate credentials",
				})
			}
		}
	}

	return unused, nil
}

// GetQuarantinedUsers finds users that appear to be quarantined (indicators of compromise)
// Based on ShinyHunters/Nemesis patterns - quarantined users indicate past breaches
func (s *service) GetQuarantinedUsers(ctx context.Context) ([]QuarantinedUser, error) {
	var quarantined []QuarantinedUser

	paginator := iam.NewListUsersPaginator(s.client, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, user := range page.Users {
			userName := *user.UserName
			var indicators []string
			quarantineType := ""

			// Check for deny-all inline policies (common quarantine pattern)
			inlinePolicies, err := s.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
				UserName: aws.String(userName),
			})
			if err == nil {
				for _, policyName := range inlinePolicies.PolicyNames {
					policyNameLower := strings.ToLower(policyName)
					if strings.Contains(policyNameLower, "quarantine") ||
						strings.Contains(policyNameLower, "deny") ||
						strings.Contains(policyNameLower, "block") ||
						strings.Contains(policyNameLower, "lockout") {
						indicators = append(indicators, "Quarantine policy: "+policyName)
						quarantineType = "DENY_ALL_POLICY"
					}
				}
			}

			// Check for all access keys disabled
			accessKeys, err := s.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: aws.String(userName),
			})
			if err == nil {
				allDisabled := true
				keyCount := 0
				for _, key := range accessKeys.AccessKeyMetadata {
					keyCount++
					if key.Status == types.StatusTypeActive {
						allDisabled = false
					}
				}
				if keyCount > 0 && allDisabled {
					indicators = append(indicators, "All access keys disabled")
					if quarantineType == "" {
						quarantineType = "DISABLED_KEYS"
					}
				}
			}

			// Check for no attached policies and no groups
			attachedPolicies, _ := s.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
				UserName: aws.String(userName),
			})
			groups, _ := s.client.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{
				UserName: aws.String(userName),
			})

			if attachedPolicies != nil && groups != nil {
				if len(attachedPolicies.AttachedPolicies) == 0 && len(groups.Groups) == 0 && len(inlinePolicies.PolicyNames) > 0 {
					// Has inline policies but no attached policies or groups - likely quarantined
					indicators = append(indicators, "No attached policies or groups")
					if quarantineType == "" {
						quarantineType = "NO_PERMISSIONS"
					}
				}
			}

			if len(indicators) > 0 {
				quarantined = append(quarantined, QuarantinedUser{
					UserName:       userName,
					UserARN:        *user.Arn,
					QuarantineType: quarantineType,
					Indicators:     indicators,
					Severity:       SeverityHigh,
					Description:    "User appears quarantined - may indicate past credential compromise",
					Recommendation: "Investigate the incident, verify cleanup is complete, delete user if no longer needed",
				})
			}
		}
	}

	return quarantined, nil
}
