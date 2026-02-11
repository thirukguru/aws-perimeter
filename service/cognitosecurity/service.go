// Package cognitosecurity provides Cognito security analysis.
package cognitosecurity

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// CognitoRisk represents a Cognito security misconfiguration.
type CognitoRisk struct {
	RiskType       string
	Severity       string
	Resource       string
	Description    string
	Recommendation string
}

type service struct {
	client *cognitoidentityprovider.Client
}

// Service is the interface for Cognito security checks.
type Service interface {
	GetCognitoSecurityRisks(ctx context.Context) ([]CognitoRisk, error)
}

// NewService creates a new Cognito security service.
func NewService(cfg aws.Config) Service {
	return &service{
		client: cognitoidentityprovider.NewFromConfig(cfg),
	}
}

// GetCognitoSecurityRisks evaluates Cognito user pools and clients for security gaps.
func (s *service) GetCognitoSecurityRisks(ctx context.Context) ([]CognitoRisk, error) {
	var risks []CognitoRisk

	poolsPaginator := cognitoidentityprovider.NewListUserPoolsPaginator(s.client, &cognitoidentityprovider.ListUserPoolsInput{
		MaxResults: aws.Int32(60),
	})

	for poolsPaginator.HasMorePages() {
		page, err := poolsPaginator.NextPage(ctx)
		if err != nil {
			// Cognito may be unavailable in region/account; don't fail whole scan.
			return risks, nil
		}

		for _, poolSummary := range page.UserPools {
			userPoolID := aws.ToString(poolSummary.Id)
			if strings.TrimSpace(userPoolID) == "" {
				continue
			}

			describeOut, err := s.client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
				UserPoolId: aws.String(userPoolID),
			})
			if err != nil || describeOut.UserPool == nil {
				continue
			}

			pool := describeOut.UserPool
			resource := cognitoResourceName(aws.ToString(pool.Name), userPoolID)

			if hasWeakPasswordOrMFAPolicy(pool.Policies, pool.MfaConfiguration) {
				risks = append(risks, CognitoRisk{
					RiskType:       "WeakPasswordOrMFAPolicy",
					Severity:       SeverityHigh,
					Resource:       resource,
					Description:    "User pool password policy and/or MFA configuration is weak",
					Recommendation: "Enforce strong password policy (length/complexity) and require MFA for user sign-in",
				})
			}

			if !userPoolEncryptionConfigured(pool.LambdaConfig) {
				risks = append(risks, CognitoRisk{
					RiskType:       "UserPoolEncryptionNotConfigured",
					Severity:       SeverityMedium,
					Resource:       resource,
					Description:    "User pool is not configured with customer-managed KMS key integration",
					Recommendation: "Configure customer-managed KMS key usage where supported for stronger encryption governance",
				})
			}

			if !advancedSecurityFeaturesEnabled(pool.UserPoolAddOns) {
				risks = append(risks, CognitoRisk{
					RiskType:       "AdvancedSecurityFeaturesDisabled",
					Severity:       SeverityMedium,
					Resource:       resource,
					Description:    "Cognito advanced security features are not enforced",
					Recommendation: "Enable and enforce Cognito advanced security features for adaptive risk protection",
				})
			}

			clientPaginator := cognitoidentityprovider.NewListUserPoolClientsPaginator(s.client, &cognitoidentityprovider.ListUserPoolClientsInput{
				UserPoolId: aws.String(userPoolID),
				MaxResults: aws.Int32(60),
			})
			for clientPaginator.HasMorePages() {
				clientPage, err := clientPaginator.NextPage(ctx)
				if err != nil {
					break
				}
				for _, clientSummary := range clientPage.UserPoolClients {
					clientID := aws.ToString(clientSummary.ClientId)
					if strings.TrimSpace(clientID) == "" {
						continue
					}
					clientOut, err := s.client.DescribeUserPoolClient(ctx, &cognitoidentityprovider.DescribeUserPoolClientInput{
						UserPoolId: aws.String(userPoolID),
						ClientId:   aws.String(clientID),
					})
					if err != nil || clientOut.UserPoolClient == nil {
						continue
					}
					client := clientOut.UserPoolClient
					clientResource := cognitoResourceName(aws.ToString(client.ClientName), clientID)

					if isPublicClientWithoutSecret(client) {
						risks = append(risks, CognitoRisk{
							RiskType:       "PublicUserPoolClientWithoutSecret",
							Severity:       SeverityHigh,
							Resource:       fmt.Sprintf("%s (%s)", resource, clientResource),
							Description:    "User pool client is configured without client secret for non-public auth flows",
							Recommendation: "Use confidential app clients with client secret where applicable and minimize public client exposure",
						})
					}

					if hasOverlyPermissiveCORS(client) {
						risks = append(risks, CognitoRisk{
							RiskType:       "OverlyPermissiveCORS",
							Severity:       SeverityMedium,
							Resource:       fmt.Sprintf("%s (%s)", resource, clientResource),
							Description:    "User pool client callback/logout URL configuration is overly permissive",
							Recommendation: "Restrict callback/logout URLs to trusted HTTPS domains and remove wildcards",
						})
					}
				}
			}
		}
	}

	return dedupeCognitoRisks(risks), nil
}

func hasWeakPasswordOrMFAPolicy(policies *cognitotypes.UserPoolPolicyType, mfaConfig cognitotypes.UserPoolMfaType) bool {
	weakPassword := true
	if policies != nil && policies.PasswordPolicy != nil {
		p := policies.PasswordPolicy
		minLen := aws.ToInt32(p.MinimumLength)
		weakPassword = minLen < 12 ||
			!p.RequireUppercase ||
			!p.RequireLowercase ||
			!p.RequireNumbers ||
			!p.RequireSymbols
	}
	weakMFA := mfaConfig == cognitotypes.UserPoolMfaTypeOff
	return weakPassword || weakMFA
}

func userPoolEncryptionConfigured(cfg *cognitotypes.LambdaConfigType) bool {
	if cfg == nil {
		return false
	}
	return strings.TrimSpace(aws.ToString(cfg.KMSKeyID)) != ""
}

func advancedSecurityFeaturesEnabled(addons *cognitotypes.UserPoolAddOnsType) bool {
	if addons == nil {
		return false
	}
	// Treat ENFORCED as secure baseline; AUDIT is better than OFF but still not enforced.
	return addons.AdvancedSecurityMode == cognitotypes.AdvancedSecurityModeTypeEnforced
}

func isPublicClientWithoutSecret(client *cognitotypes.UserPoolClientType) bool {
	if client == nil {
		return false
	}
	noSecret := strings.TrimSpace(aws.ToString(client.ClientSecret)) == ""
	if !noSecret {
		return false
	}
	// Flag if this client is configured for OAuth user-pool client mode or explicit auth flows
	// that are typically used by browser/mobile and backend auth surfaces.
	hasOAuthSurface := aws.ToBool(client.AllowedOAuthFlowsUserPoolClient) ||
		len(client.AllowedOAuthFlows) > 0 ||
		len(client.ExplicitAuthFlows) > 0
	return hasOAuthSurface
}

func hasOverlyPermissiveCORS(client *cognitotypes.UserPoolClientType) bool {
	if client == nil {
		return false
	}
	urls := append([]string{}, client.CallbackURLs...)
	urls = append(urls, client.LogoutURLs...)
	for _, u := range urls {
		url := strings.TrimSpace(strings.ToLower(u))
		if url == "" {
			continue
		}
		if strings.Contains(url, "*") {
			return true
		}
		if strings.HasPrefix(url, "http://") && !strings.Contains(url, "localhost") && !strings.Contains(url, "127.0.0.1") {
			return true
		}
	}
	return false
}

func cognitoResourceName(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

func dedupeCognitoRisks(in []CognitoRisk) []CognitoRisk {
	seen := map[string]bool{}
	out := make([]CognitoRisk, 0, len(in))
	for _, r := range in {
		key := r.RiskType + "|" + r.Resource
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b CognitoRisk) int {
		if a.RiskType == b.RiskType {
			return strings.Compare(a.Resource, b.Resource)
		}
		return strings.Compare(a.RiskType, b.RiskType)
	})
	return out
}
