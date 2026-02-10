package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/aidetection"
	"github.com/thirukguru/aws-perimeter/service/iam"
	"github.com/thirukguru/aws-perimeter/service/resourcepolicy"
	"github.com/thirukguru/aws-perimeter/service/storage"
)

func findingHash(parts ...string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%q", parts)))
	return hex.EncodeToString(h[:])
}

func (s *service) persistScanIfEnabled(
	ctx context.Context,
	flags model.Flags,
	accountID string,
	region string,
	duration time.Duration,
	vpcInput model.RenderSecurityInput,
	iamInput model.RenderIAMInput,
	s3Input model.RenderS3Input,
	ctInput model.RenderCloudTrailInput,
	secretsInput model.RenderSecretsInput,
	advInput model.RenderAdvancedInput,
	aiRisks []aidetection.AIRisk,
) error {
	if s.storageService == nil || !flags.Store {
		return nil
	}

	findings := []storage.Finding{}
	countBySev := map[string]int{}
	add := func(f storage.Finding) {
		if f.Hash == "" {
			f.Hash = findingHash(f.Category, f.RiskType, f.ResourceID, f.Title)
		}
		findings = append(findings, f)
		countBySev[f.Severity]++
	}

	for _, r := range vpcInput.SecurityGroupRisks {
		add(storage.Finding{Hash: findingHash("VPC", r.RiskType, r.SecurityGroupID), Category: "VPC", Subcategory: "SecurityGroup", RiskType: r.RiskType, Severity: r.Severity, ResourceType: "SecurityGroup", ResourceID: r.SecurityGroupID, Title: "Security Group Risk", Description: r.Description, Recommendation: r.Recommendation})
	}
	for _, r := range vpcInput.PublicExposureRisks {
		add(storage.Finding{Hash: findingHash("VPC", "PublicExposure", r.InstanceID), Category: "VPC", Subcategory: "Exposure", RiskType: "PublicExposure", Severity: r.Severity, ResourceType: "EC2Instance", ResourceID: r.InstanceID, Title: "Public Exposure", Description: r.Description, Recommendation: r.Recommendation})
	}
	for _, r := range vpcInput.NACLRisks {
		add(storage.Finding{Hash: findingHash("VPC", "NACL", r.NetworkAclID, fmt.Sprintf("%d", r.RuleNumber)), Category: "VPC", Subcategory: "NACL", RiskType: "NACL", Severity: r.Severity, ResourceType: "NetworkACL", ResourceID: r.NetworkAclID, Title: "NACL Risk", Description: r.Description})
	}
	for _, r := range iamInput.PrivilegeEscalation {
		add(storage.Finding{Hash: findingHash("IAM", r.EscalationPath, r.PrincipalARN), Category: "IAM", Subcategory: "PrivilegeEscalation", RiskType: r.EscalationPath, Severity: r.Severity, ResourceType: r.PrincipalType, ResourceID: r.PrincipalARN, Title: "Privilege Escalation", Description: "Privilege escalation path detected", Recommendation: r.Recommendation})
	}
	for _, r := range iamInput.CrossAccountTrusts {
		add(storage.Finding{Hash: findingHash("IAM", "CrossAccountTrust", r.RoleARN, r.TrustedPrincipal), Category: "IAM", Subcategory: "Trust", RiskType: "CrossAccountTrust", Severity: r.Severity, ResourceType: "Role", ResourceID: r.RoleARN, Title: "Cross Account Trust", Description: r.Description, Recommendation: r.Recommendation})
	}
	for _, r := range iamInput.OverlyPermissivePolicies {
		desc := "Overly permissive policy detected"
		if len(r.DangerousStmts) > 0 && r.DangerousStmts[0].Reason != "" {
			desc = r.DangerousStmts[0].Reason
		}
		add(storage.Finding{Hash: findingHash("IAM", "OverlyPermissivePolicy", r.PolicyARN), Category: "IAM", Subcategory: "Policy", RiskType: "OverlyPermissivePolicy", Severity: iam.SeverityCritical, ResourceType: "Policy", ResourceID: r.PolicyARN, Title: "Overly Permissive Policy", Description: desc, Recommendation: r.Recommendation})
	}
	for _, r := range s3Input.PublicBuckets {
		add(storage.Finding{Hash: findingHash("S3", r.RiskType, r.BucketName), Category: "S3", Subcategory: "Bucket", RiskType: r.RiskType, Severity: r.Severity, ResourceType: "Bucket", ResourceID: r.BucketName, Title: "Public Bucket", Description: r.Description, Recommendation: r.Recommendation})
	}
	for _, r := range s3Input.UnencryptedBkts {
		add(storage.Finding{Hash: findingHash("S3", "UnencryptedBucket", r.BucketName), Category: "S3", Subcategory: "Encryption", RiskType: "UnencryptedBucket", Severity: r.Severity, ResourceType: "Bucket", ResourceID: r.BucketName, Title: "Unencrypted Bucket", Description: "Bucket encryption is not configured"})
	}
	for _, r := range ctInput.TrailGaps {
		add(storage.Finding{Hash: findingHash("CloudTrail", r.Issue), Category: "CloudTrail", Subcategory: "Coverage", RiskType: r.Issue, Severity: r.Severity, ResourceType: "CloudTrail", ResourceID: r.Issue, Title: "CloudTrail Gap", Description: r.Description, Recommendation: r.Recommendation})
	}
	for _, r := range secretsInput.LambdaSecrets {
		add(storage.Finding{Hash: findingHash("Secrets", r.SecretType, r.ResourceID, r.Location), Category: "Secrets", Subcategory: "Lambda", RiskType: r.SecretType, Severity: r.Severity, ResourceType: r.ResourceType, ResourceID: r.ResourceID, Title: "Secret Detected", Description: r.Location, Recommendation: r.Recommendation})
	}
	for _, r := range secretsInput.EC2Secrets {
		add(storage.Finding{Hash: findingHash("Secrets", r.SecretType, r.ResourceID, r.Location), Category: "Secrets", Subcategory: "EC2", RiskType: r.SecretType, Severity: r.Severity, ResourceType: r.ResourceType, ResourceID: r.ResourceID, Title: "Secret Detected", Description: r.Location, Recommendation: r.Recommendation})
	}
	for _, r := range secretsInput.S3Secrets {
		add(storage.Finding{Hash: findingHash("Secrets", r.SecretType, r.ResourceID, r.Location), Category: "Secrets", Subcategory: "S3", RiskType: r.SecretType, Severity: r.Severity, ResourceType: r.ResourceType, ResourceID: r.ResourceID, Title: "Secret Detected", Description: r.Location, Recommendation: r.Recommendation})
	}
	for _, r := range secretsInput.ECRSecrets {
		add(storage.Finding{Hash: findingHash("Secrets", r.SecretType, r.ResourceID, r.Location), Category: "Secrets", Subcategory: "ECR", RiskType: r.SecretType, Severity: r.Severity, ResourceType: r.ResourceType, ResourceID: r.ResourceID, Title: "Secret Detected", Description: r.Location, Recommendation: r.Recommendation})
	}
	for _, r := range advInput.GuardDutyFindings {
		add(storage.Finding{Hash: findingHash("GuardDuty", r.Type, r.ResourceID), Category: "GuardDuty", Subcategory: "Threat", RiskType: r.Type, Severity: r.SeverityLabel, ResourceType: "AWSResource", ResourceID: r.ResourceID, Title: "GuardDuty Finding", Description: r.Description})
	}
	for _, r := range advInput.APINoAuth {
		add(storage.Finding{Hash: findingHash("APIGateway", "NoAuth", r.APIName, r.RouteKey), Category: "APIGateway", Subcategory: "Auth", RiskType: "NoAuth", Severity: r.Severity, ResourceType: "APIRoute", ResourceID: r.APIID + ":" + r.RouteKey, Title: "API Route Without Auth", Description: "API route has no authorization configured", Recommendation: r.Recommendation})
	}
	appendPolicyFindings := func(kind string, items []resourcepolicy.ResourcePolicyRisk) {
		for _, r := range items {
			add(storage.Finding{Hash: findingHash("ResourcePolicy", kind, r.ResourceName, r.RiskType), Category: "ResourcePolicy", Subcategory: kind, RiskType: r.RiskType, Severity: r.Severity, ResourceType: r.ResourceType, ResourceID: r.ResourceName, Title: "Resource Policy Risk", Description: r.Description, Recommendation: r.Recommendation})
		}
	}
	appendPolicyFindings("Lambda", advInput.LambdaPolicyRisks)
	appendPolicyFindings("SQS", advInput.SQSPolicyRisks)
	appendPolicyFindings("SNS", advInput.SNSPolicyRisks)
	for _, r := range aiRisks {
		add(storage.Finding{Hash: findingHash("AI", r.RiskType, r.Resource), Category: "AI", Subcategory: "AttackDetection", RiskType: r.RiskType, Severity: r.Severity, ResourceType: "AWSResource", ResourceID: r.Resource, Title: "AI Attack Indicator", Description: r.Description, Recommendation: r.Recommendation})
	}

	flagsJSON, _ := json.Marshal(flags)
	_, err := s.storageService.SaveScan(ctx, storage.SaveScanInput{
		ScanUUID:      fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		AccountID:     accountID,
		Region:        region,
		DurationSec:   int64(duration.Seconds()),
		Version:       s.versionInfo.Version,
		Profile:       flags.Profile,
		FlagsJSON:     string(flagsJSON),
		CriticalCount: countBySev["CRITICAL"],
		HighCount:     countBySev["HIGH"],
		MediumCount:   countBySev["MEDIUM"],
		LowCount:      countBySev["LOW"],
		InfoCount:     countBySev["INFO"],
		Findings:      findings,
	})
	return err
}
