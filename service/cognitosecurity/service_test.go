package cognitosecurity

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

func TestHasWeakPasswordOrMFAPolicy(t *testing.T) {
	strongPolicy := &cognitotypes.UserPoolPolicyType{
		PasswordPolicy: &cognitotypes.PasswordPolicyType{
			MinimumLength:    aws.Int32(12),
			RequireUppercase: true,
			RequireLowercase: true,
			RequireNumbers:   true,
			RequireSymbols:   true,
		},
	}
	if hasWeakPasswordOrMFAPolicy(strongPolicy, cognitotypes.UserPoolMfaTypeOn) {
		t.Fatalf("did not expect strong password+MFA config to be weak")
	}
	if !hasWeakPasswordOrMFAPolicy(strongPolicy, cognitotypes.UserPoolMfaTypeOff) {
		t.Fatalf("expected MFA OFF to be flagged")
	}
	weakPolicy := &cognitotypes.UserPoolPolicyType{
		PasswordPolicy: &cognitotypes.PasswordPolicyType{
			MinimumLength:    aws.Int32(8),
			RequireUppercase: false,
			RequireLowercase: true,
			RequireNumbers:   true,
			RequireSymbols:   false,
		},
	}
	if !hasWeakPasswordOrMFAPolicy(weakPolicy, cognitotypes.UserPoolMfaTypeOn) {
		t.Fatalf("expected weak password policy to be flagged")
	}
}

func TestUserPoolEncryptionConfigured(t *testing.T) {
	if userPoolEncryptionConfigured(nil) {
		t.Fatalf("did not expect nil config to be treated as encrypted")
	}
	if userPoolEncryptionConfigured(&cognitotypes.LambdaConfigType{}) {
		t.Fatalf("did not expect empty KMS key to be treated as encrypted")
	}
	if !userPoolEncryptionConfigured(&cognitotypes.LambdaConfigType{KMSKeyID: aws.String("arn:aws:kms:us-east-1:123:key/abc")}) {
		t.Fatalf("expected KMS key config to be treated as encrypted-governed")
	}
}

func TestAdvancedSecurityFeaturesEnabled(t *testing.T) {
	if advancedSecurityFeaturesEnabled(nil) {
		t.Fatalf("did not expect nil addons to be enabled")
	}
	if advancedSecurityFeaturesEnabled(&cognitotypes.UserPoolAddOnsType{AdvancedSecurityMode: cognitotypes.AdvancedSecurityModeTypeOff}) {
		t.Fatalf("did not expect OFF mode to be enabled")
	}
	if !advancedSecurityFeaturesEnabled(&cognitotypes.UserPoolAddOnsType{AdvancedSecurityMode: cognitotypes.AdvancedSecurityModeTypeEnforced}) {
		t.Fatalf("expected ENFORCED mode to be enabled")
	}
}

func TestIsPublicClientWithoutSecret(t *testing.T) {
	client := &cognitotypes.UserPoolClientType{
		ClientSecret:                    nil,
		AllowedOAuthFlowsUserPoolClient: aws.Bool(true),
	}
	if !isPublicClientWithoutSecret(client) {
		t.Fatalf("expected OAuth public client without secret to be flagged")
	}
	client.ClientSecret = aws.String("secret")
	if isPublicClientWithoutSecret(client) {
		t.Fatalf("did not expect client with secret to be flagged")
	}
}

func TestHasOverlyPermissiveCORS(t *testing.T) {
	client := &cognitotypes.UserPoolClientType{
		CallbackURLs: []string{"https://app.example.com/callback"},
		LogoutURLs:   []string{"https://app.example.com/logout"},
	}
	if hasOverlyPermissiveCORS(client) {
		t.Fatalf("did not expect strict HTTPS callbacks to be flagged")
	}
	client.CallbackURLs = []string{"https://*.example.com/callback"}
	if !hasOverlyPermissiveCORS(client) {
		t.Fatalf("expected wildcard callback to be flagged")
	}
	client.CallbackURLs = []string{"http://evil.example.com/callback"}
	if !hasOverlyPermissiveCORS(client) {
		t.Fatalf("expected non-localhost HTTP callback to be flagged")
	}
}
