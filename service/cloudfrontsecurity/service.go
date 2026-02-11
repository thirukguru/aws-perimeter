// Package cloudfrontsecurity provides CloudFront distribution security analysis.
package cloudfrontsecurity

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// CloudFrontRisk represents a security finding for a CloudFront distribution
type CloudFrontRisk struct {
	DistributionID string
	DomainName     string
	Aliases        []string
	RiskType       string
	Severity       string
	Description    string
	Recommendation string
}

// Service is the interface for CloudFront security analysis
type Service interface {
	GetCloudFrontRisks(ctx context.Context) ([]CloudFrontRisk, error)
}

type service struct {
	cfClient  *cloudfront.Client
	wafClient *wafv2.Client
}

// NewService creates a new CloudFront security service
func NewService(cfg aws.Config) Service {
	return &service{
		cfClient:  cloudfront.NewFromConfig(cfg),
		wafClient: wafv2.NewFromConfig(cfg),
	}
}

// GetCloudFrontRisks analyzes CloudFront distributions for security issues
func (s *service) GetCloudFrontRisks(ctx context.Context) ([]CloudFrontRisk, error) {
	var risks []CloudFrontRisk

	// List all CloudFront distributions
	paginator := cloudfront.NewListDistributionsPaginator(s.cfClient, &cloudfront.ListDistributionsInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		if output.DistributionList == nil || output.DistributionList.Items == nil {
			continue
		}

		for _, dist := range output.DistributionList.Items {
			distID := aws.ToString(dist.Id)
			domainName := aws.ToString(dist.DomainName)

			var aliases []string
			if dist.Aliases != nil && dist.Aliases.Items != nil {
				aliases = dist.Aliases.Items
			}

			// Check 1: Viewer Protocol Policy - should require HTTPS
			if dist.DefaultCacheBehavior != nil {
				if dist.DefaultCacheBehavior.ViewerProtocolPolicy == types.ViewerProtocolPolicyAllowAll {
					risks = append(risks, CloudFrontRisk{
						DistributionID: distID,
						DomainName:     domainName,
						Aliases:        aliases,
						RiskType:       "HTTP_ALLOWED",
						Severity:       SeverityHigh,
						Description:    "CloudFront distribution allows HTTP traffic. This enables man-in-the-middle attacks.",
						Recommendation: "Set ViewerProtocolPolicy to 'redirect-to-https' or 'https-only' in the default cache behavior.",
					})
				}
			}

			// Check 2: Minimum TLS version
			if dist.ViewerCertificate != nil {
				minProtocol := dist.ViewerCertificate.MinimumProtocolVersion
				if minProtocol == types.MinimumProtocolVersionSSLv3 ||
					minProtocol == types.MinimumProtocolVersionTLSv1 ||
					minProtocol == types.MinimumProtocolVersionTLSv12016 {
					risks = append(risks, CloudFrontRisk{
						DistributionID: distID,
						DomainName:     domainName,
						Aliases:        aliases,
						RiskType:       "WEAK_TLS",
						Severity:       SeverityMedium,
						Description:    "CloudFront distribution uses TLS version older than 1.2. This is vulnerable to protocol downgrade attacks.",
						Recommendation: "Update MinimumProtocolVersion to TLSv1.2_2021 or newer.",
					})
				}
			}

			// Check 3: WAF not associated
			if dist.WebACLId == nil || aws.ToString(dist.WebACLId) == "" {
				risks = append(risks, CloudFrontRisk{
					DistributionID: distID,
					DomainName:     domainName,
					Aliases:        aliases,
					RiskType:       "NO_WAF",
					Severity:       SeverityMedium,
					Description:    "CloudFront distribution does not have a WAF Web ACL associated. This leaves it vulnerable to common web attacks.",
					Recommendation: "Associate an AWS WAF Web ACL with this distribution to protect against SQL injection, XSS, and other attacks.",
				})
			}

			// Check 4: Access logging disabled (requires full distribution config)
			configOut, err := s.cfClient.GetDistributionConfig(ctx, &cloudfront.GetDistributionConfigInput{
				Id: dist.Id,
			})
			if err == nil && configOut != nil && configOut.DistributionConfig != nil &&
				configOut.DistributionConfig.Logging != nil &&
				!aws.ToBool(configOut.DistributionConfig.Logging.Enabled) {
				risks = append(risks, CloudFrontRisk{
					DistributionID: distID,
					DomainName:     domainName,
					Aliases:        aliases,
					RiskType:       "NO_LOGGING",
					Severity:       SeverityLow,
					Description:    "CloudFront distribution does not have access logging enabled. This limits security visibility.",
					Recommendation: "Enable access logging to an S3 bucket for security monitoring and compliance.",
				})
			}

			// Check 5: Origin Protocol Policy - should use HTTPS to origin
			if dist.Origins != nil && dist.Origins.Items != nil {
				for _, origin := range dist.Origins.Items {
					if origin.CustomOriginConfig != nil {
						if origin.CustomOriginConfig.OriginProtocolPolicy == types.OriginProtocolPolicyHttpOnly {
							risks = append(risks, CloudFrontRisk{
								DistributionID: distID,
								DomainName:     domainName,
								Aliases:        aliases,
								RiskType:       "HTTP_TO_ORIGIN",
								Severity:       SeverityHigh,
								Description:    "CloudFront uses HTTP to communicate with origin '" + aws.ToString(origin.DomainName) + "'. Data in transit is not encrypted.",
								Recommendation: "Set OriginProtocolPolicy to 'https-only' or 'match-viewer' for origin " + aws.ToString(origin.DomainName),
							})
						}
					}
				}
			}

			// Check 6: Geo-restriction not configured (informational)
			if dist.Restrictions != nil && dist.Restrictions.GeoRestriction != nil {
				if dist.Restrictions.GeoRestriction.RestrictionType == types.GeoRestrictionTypeNone {
					// Only flag if distribution has aliases (custom domain) - indicates production use
					if len(aliases) > 0 {
						risks = append(risks, CloudFrontRisk{
							DistributionID: distID,
							DomainName:     domainName,
							Aliases:        aliases,
							RiskType:       "NO_GEO_RESTRICTION",
							Severity:       SeverityLow,
							Description:    "CloudFront distribution has no geographic restrictions configured.",
							Recommendation: "Consider enabling geo-restriction if your content should only be accessed from specific countries.",
						})
					}
				}
			}
		}
	}

	return risks, nil
}

// getWebACLDetails retrieves details about a WAF Web ACL
func (s *service) getWebACLDetails(ctx context.Context, webACLID string) (*waftypes.WebACL, error) {
	// Parse the ARN to get the name and scope
	parts := strings.Split(webACLID, "/")
	if len(parts) < 3 {
		return nil, nil
	}

	output, err := s.wafClient.GetWebACL(ctx, &wafv2.GetWebACLInput{
		Id:    aws.String(parts[len(parts)-1]),
		Name:  aws.String(parts[len(parts)-2]),
		Scope: waftypes.ScopeCloudfront,
	})
	if err != nil {
		return nil, err
	}

	return output.WebACL, nil
}
