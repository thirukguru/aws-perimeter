package jsonoutput

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/thirukguru/aws-perimeter/model"
	iamService "github.com/thirukguru/aws-perimeter/service/iam"
	vpcService "github.com/thirukguru/aws-perimeter/service/vpc"
)

// OutputSecurityJSON outputs security analysis data as JSON
func OutputSecurityJSON(input model.RenderSecurityInput) error {
	output := BuildSecurityReport(input, time.Now().UTC().Format(time.RFC3339))
	return printJSON(output)
}

// BuildSecurityReport builds the security JSON report model.
func BuildSecurityReport(input model.RenderSecurityInput, generatedAt string) model.SecurityReportJSON {
	criticalCount, highCount, mediumCount, lowCount, infoCount := countSecuritySeverities(input)
	totalFindings := criticalCount + highCount + mediumCount + lowCount + infoCount

	return model.SecurityReportJSON{
		AccountID:   input.AccountID,
		Region:      input.Region,
		GeneratedAt: generatedAt,
		HasFindings: totalFindings > 0,
		Summary: model.SecuritySummaryJSON{
			TotalFindings: totalFindings,
			Critical:      criticalCount,
			High:          highCount,
			Medium:        mediumCount,
			Low:           lowCount,
			Info:          infoCount,
		},
		SecurityGroupRisks:   mapSGRisks(input.SecurityGroupRisks),
		UnusedSecurityGroups: mapUnusedSGs(input.UnusedSecurityGroups),
		PublicExposureRisks:  mapExposureRisks(input.PublicExposureRisks),
		NACLRisks:            mapNACLRisks(input.NACLRisks),
		VPCFlowLogStatus:     mapFlowLogStatus(input.VPCFlowLogStatus),
	}
}

func countSecuritySeverities(input model.RenderSecurityInput) (critical, high, medium, low, info int) {
	for _, r := range input.SecurityGroupRisks {
		switch r.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		case "INFO":
			info++
		}
	}

	for _, r := range input.PublicExposureRisks {
		switch r.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		}
	}

	for _, r := range input.NACLRisks {
		switch r.Severity {
		case "MEDIUM":
			medium++
		}
	}

	for _, s := range input.VPCFlowLogStatus {
		if !s.FlowLogsEnabled {
			medium++
		}
	}

	info += len(input.UnusedSecurityGroups)

	return
}

func mapSGRisks(risks []vpcService.SGRisk) []model.SecurityGroupRiskJSON {
	var result []model.SecurityGroupRiskJSON

	for _, r := range risks {
		result = append(result, model.SecurityGroupRiskJSON{
			SecurityGroupID:   r.SecurityGroupID,
			SecurityGroupName: r.SecurityGroupName,
			VpcID:             r.VpcID,
			RiskType:          r.RiskType,
			Severity:          r.Severity,
			Port:              r.Port,
			Protocol:          r.Protocol,
			SourceCIDR:        r.SourceCIDR,
			Description:       r.Description,
			Recommendation:    r.Recommendation,
			AffectedResources: r.AffectedResources,
		})
	}

	return result
}

func mapUnusedSGs(unused []vpcService.UnusedSG) []model.UnusedSGJSON {
	var result []model.UnusedSGJSON

	for _, sg := range unused {
		result = append(result, model.UnusedSGJSON{
			SecurityGroupID:   sg.SecurityGroupID,
			SecurityGroupName: sg.SecurityGroupName,
			VpcID:             sg.VpcID,
			Description:       sg.Description,
		})
	}

	return result
}

func mapExposureRisks(risks []vpcService.ExposureRisk) []model.ExposureRiskJSON {
	var result []model.ExposureRiskJSON

	for _, r := range risks {
		result = append(result, model.ExposureRiskJSON{
			InstanceID:       r.InstanceID,
			InstanceName:     r.InstanceName,
			PublicIP:         r.PublicIP,
			SecurityGroupIDs: r.SecurityGroupIDs,
			OpenPorts:        r.OpenPorts,
			Severity:         r.Severity,
			Description:      r.Description,
			Recommendation:   r.Recommendation,
		})
	}

	return result
}

func mapNACLRisks(risks []vpcService.NACLRisk) []model.NACLRiskJSON {
	var result []model.NACLRiskJSON

	for _, r := range risks {
		result = append(result, model.NACLRiskJSON{
			NetworkAclID: r.NetworkAclID,
			VpcID:        r.VpcID,
			SubnetIDs:    r.SubnetIDs,
			RuleNumber:   r.RuleNumber,
			IsEgress:     r.IsEgress,
			Protocol:     r.Protocol,
			PortRange:    r.PortRange,
			CidrBlock:    r.CidrBlock,
			RuleAction:   r.RuleAction,
			Severity:     r.Severity,
			Description:  r.Description,
		})
	}

	return result
}

func mapFlowLogStatus(statuses []vpcService.FlowLogStatus) []model.FlowLogStatusJSON {
	var result []model.FlowLogStatusJSON

	for _, s := range statuses {
		result = append(result, model.FlowLogStatusJSON{
			VpcID:           s.VpcID,
			VpcName:         s.VpcName,
			FlowLogsEnabled: s.FlowLogsEnabled,
			FlowLogIDs:      s.FlowLogIDs,
			Severity:        s.Severity,
			Recommendation:  s.Recommendation,
		})
	}

	return result
}

func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(data))

	return nil
}

// OutputIAMJSON outputs IAM security analysis data as JSON
func OutputIAMJSON(input model.RenderIAMInput) error {
	output := BuildIAMReport(input, time.Now().UTC().Format(time.RFC3339))
	return printJSON(output)
}

// BuildIAMReport builds the IAM JSON report model.
func BuildIAMReport(input model.RenderIAMInput, generatedAt string) model.IAMReportJSON {
	critical, high, medium, low, info := countIAMSeverities(input)
	totalFindings := critical + high + medium + low + info

	return model.IAMReportJSON{
		AccountID:   input.AccountID,
		Region:      input.Region,
		GeneratedAt: generatedAt,
		HasFindings: totalFindings > 0,
		Summary: model.IAMSummaryJSON{
			TotalFindings: totalFindings,
			Critical:      critical,
			High:          high,
			Medium:        medium,
			Low:           low,
			Info:          info,
		},
		PrivilegeEscalation:      mapPrivEscRisks(input.PrivilegeEscalation),
		StaleCredentials:         mapStaleCreds(input.StaleCredentials),
		CrossAccountTrusts:       mapCrossAccountTrusts(input.CrossAccountTrusts),
		UsersWithoutMFA:          mapMFAStatus(input.UsersWithoutMFA),
		OverlyPermissivePolicies: mapDangerousPolicies(input.OverlyPermissivePolicies),
	}
}

func countIAMSeverities(input model.RenderIAMInput) (critical, high, medium, low, info int) {
	for _, r := range input.PrivilegeEscalation {
		switch r.Severity {
		case iamService.SeverityCritical:
			critical++
		case iamService.SeverityHigh:
			high++
		case iamService.SeverityMedium:
			medium++
		}
	}

	for _, c := range input.StaleCredentials {
		switch c.Severity {
		case iamService.SeverityHigh:
			high++
		case iamService.SeverityMedium:
			medium++
		}
	}

	for _, t := range input.CrossAccountTrusts {
		switch t.Severity {
		case iamService.SeverityCritical:
			critical++
		case iamService.SeverityHigh:
			high++
		}
	}

	medium += len(input.UsersWithoutMFA)
	critical += len(input.OverlyPermissivePolicies)

	return
}

func mapPrivEscRisks(risks []iamService.PrivEscRisk) []model.PrivEscRiskJSON {
	var result []model.PrivEscRiskJSON
	for _, r := range risks {
		result = append(result, model.PrivEscRiskJSON{
			PrincipalType:    r.PrincipalType,
			PrincipalName:    r.PrincipalName,
			PrincipalARN:     r.PrincipalARN,
			EscalationPath:   r.EscalationPath,
			DangerousActions: r.DangerousActions,
			Severity:         r.Severity,
			Recommendation:   r.Recommendation,
		})
	}
	return result
}

func mapStaleCreds(creds []iamService.StaleCredential) []model.StaleCredentialJSON {
	var result []model.StaleCredentialJSON
	for _, c := range creds {
		result = append(result, model.StaleCredentialJSON{
			UserName:          c.UserName,
			CredentialType:    c.CredentialType,
			AccessKeyID:       c.AccessKeyID,
			CreatedDate:       c.CreatedDate,
			LastUsedDate:      c.LastUsedDate,
			DaysSinceLastUse:  c.DaysSinceLastUse,
			DaysSinceCreation: c.DaysSinceCreation,
			Severity:          c.Severity,
			Recommendation:    c.Recommendation,
		})
	}
	return result
}

func mapCrossAccountTrusts(trusts []iamService.CrossAccountTrust) []model.CrossAccountTrustJSON {
	var result []model.CrossAccountTrustJSON
	for _, t := range trusts {
		result = append(result, model.CrossAccountTrustJSON{
			RoleName:           t.RoleName,
			RoleARN:            t.RoleARN,
			TrustedAccountID:   t.TrustedAccountID,
			TrustedPrincipal:   t.TrustedPrincipal,
			IsExternalAccount:  t.IsExternalAccount,
			AllowsAnyPrincipal: t.AllowsAnyPrincipal,
			Severity:           t.Severity,
			Description:        t.Description,
			Recommendation:     t.Recommendation,
		})
	}
	return result
}

func mapMFAStatus(users []iamService.UserMFAStatus) []model.UserMFAStatusJSON {
	var result []model.UserMFAStatusJSON
	for _, u := range users {
		result = append(result, model.UserMFAStatusJSON{
			UserName:       u.UserName,
			UserARN:        u.UserARN,
			HasConsolePwd:  u.HasConsolePwd,
			MFAEnabled:     u.MFAEnabled,
			Severity:       u.Severity,
			Recommendation: u.Recommendation,
		})
	}
	return result
}

func mapDangerousPolicies(policies []iamService.DangerousPolicy) []model.DangerousPolicyJSON {
	var result []model.DangerousPolicyJSON
	for _, p := range policies {
		reason := "Full admin access"
		if len(p.DangerousStmts) > 0 {
			reason = p.DangerousStmts[0].Reason
		}
		result = append(result, model.DangerousPolicyJSON{
			PolicyName:     p.PolicyName,
			PolicyARN:      p.PolicyARN,
			PolicyType:     p.PolicyType,
			Severity:       p.Severity,
			Reason:         reason,
			Recommendation: p.Recommendation,
		})
	}
	return result
}

// OutputS3JSON outputs S3 security analysis as JSON
func OutputS3JSON(input model.RenderS3Input) error {
	output := BuildS3Report(input, time.Now().UTC().Format(time.RFC3339))
	return printJSON(output)
}

// BuildS3Report builds the S3 JSON report model.
func BuildS3Report(input model.RenderS3Input, generatedAt string) model.S3ReportJSON {
	output := model.S3ReportJSON{
		AccountID:   input.AccountID,
		Region:      input.Region,
		GeneratedAt: generatedAt,
		HasFindings: len(input.PublicBuckets)+len(input.UnencryptedBkts)+len(input.RiskyPolicies)+len(input.SensitiveExposures) > 0,
	}

	for _, b := range input.PublicBuckets {
		output.PublicBuckets = append(output.PublicBuckets, model.BucketRiskJSON{
			BucketName:     b.BucketName,
			RiskType:       b.RiskType,
			Severity:       b.Severity,
			Description:    b.Description,
			Recommendation: b.Recommendation,
		})
	}

	for _, b := range input.UnencryptedBkts {
		output.UnencryptedBkts = append(output.UnencryptedBkts, model.BucketEncJSON{
			BucketName:     b.BucketName,
			IsEncrypted:    b.IsEncrypted,
			EncryptionType: b.EncryptionType,
			Severity:       b.Severity,
		})
	}

	for _, p := range input.RiskyPolicies {
		output.RiskyPolicies = append(output.RiskyPolicies, model.BucketPolicyJSON{
			BucketName:      p.BucketName,
			AllowsPublic:    p.AllowsPublic,
			AllowsAnyAction: p.AllowsAnyAction,
			RiskyStatements: p.RiskyStatements,
			Severity:        p.Severity,
		})
	}

	for _, e := range input.SensitiveExposures {
		output.SensitiveExposures = append(output.SensitiveExposures, model.SensitiveFileExposureJSON{
			BucketName:     e.BucketName,
			FileName:       e.FileName,
			FileType:       e.FileType,
			IsPublic:       e.IsPublic,
			Severity:       e.Severity,
			Description:    e.Description,
			Recommendation: e.Recommendation,
		})
	}

	return output
}

// OutputCloudTrailJSON outputs CloudTrail analysis as JSON
func OutputCloudTrailJSON(input model.RenderCloudTrailInput) error {
	output := BuildCloudTrailReport(input, time.Now().UTC().Format(time.RFC3339))
	return printJSON(output)
}

// BuildCloudTrailReport builds the CloudTrail JSON report model.
func BuildCloudTrailReport(input model.RenderCloudTrailInput, generatedAt string) model.CloudTrailReportJSON {
	output := model.CloudTrailReportJSON{
		AccountID:   input.AccountID,
		Region:      input.Region,
		GeneratedAt: generatedAt,
		HasFindings: len(input.TrailGaps) > 0,
	}

	for _, t := range input.TrailStatus {
		output.Trails = append(output.Trails, model.TrailJSON{
			TrailName:        t.TrailName,
			IsMultiRegion:    t.IsMultiRegion,
			IsLogging:        t.IsLogging,
			HasLogValidation: t.HasLogValidation,
			Severity:         t.Severity,
		})
	}

	for _, g := range input.TrailGaps {
		output.Gaps = append(output.Gaps, model.TrailGapJSON{
			Issue:          g.Issue,
			Severity:       g.Severity,
			Description:    g.Description,
			Recommendation: g.Recommendation,
		})
	}

	return output
}

// OutputSecretsJSON outputs secrets detection results as JSON
func OutputSecretsJSON(input model.RenderSecretsInput) error {
	output := BuildSecretsReport(input, time.Now().UTC().Format(time.RFC3339))
	return printJSON(output)
}

// BuildSecretsReport builds the secrets JSON report model.
func BuildSecretsReport(input model.RenderSecretsInput, generatedAt string) model.SecretsReportJSON {
	allSecrets := append(input.LambdaSecrets, input.EC2Secrets...)
	allSecrets = append(allSecrets, input.S3Secrets...)
	allSecrets = append(allSecrets, input.ECRSecrets...)

	output := model.SecretsReportJSON{
		AccountID:   input.AccountID,
		Region:      input.Region,
		GeneratedAt: generatedAt,
		HasFindings: len(allSecrets) > 0,
		TotalCount:  len(allSecrets),
	}

	for _, s := range allSecrets {
		output.Secrets = append(output.Secrets, model.SecretJSON{
			ResourceType:   s.ResourceType,
			ResourceID:     s.ResourceID,
			ResourceName:   s.ResourceName,
			SecretType:     s.SecretType,
			Location:       s.Location,
			Severity:       s.Severity,
			Recommendation: s.Recommendation,
		})
	}

	return output
}

// OutputAdvancedJSON outputs advanced security findings as JSON
func OutputAdvancedJSON(input model.RenderAdvancedInput) error {
	output := BuildAdvancedReport(input, time.Now().UTC().Format(time.RFC3339))
	return printJSON(output)
}

// BuildAdvancedReport builds the advanced security JSON report model.
func BuildAdvancedReport(input model.RenderAdvancedInput, generatedAt string) model.AdvancedReportJSON {
	allPolicyRisks := append(input.LambdaPolicyRisks, input.SQSPolicyRisks...)
	allPolicyRisks = append(allPolicyRisks, input.SNSPolicyRisks...)

	output := model.AdvancedReportJSON{
		AccountID:   input.AccountID,
		Region:      input.Region,
		GeneratedAt: generatedAt,
	}

	if input.HubStatus != nil {
		output.SecurityHubEnabled = input.HubStatus.IsEnabled
	}
	output.SecurityHubFindings = input.HubFindings

	if input.GuardDutyStatus != nil {
		output.GuardDutyEnabled = input.GuardDutyStatus.IsEnabled
	}
	output.GuardDutyFindings = input.GuardDutyFindings

	output.APIsWithoutRateLimits = input.APINoRateLimits
	output.APIsWithoutAuth = input.APINoAuth
	output.ResourcePolicyRisks = allPolicyRisks
	output.MessagingSecurityRisks = input.MessagingSecurityRisks
	output.ECRSecurityRisks = input.ECRSecurityRisks
	output.BackupRisks = input.BackupRisks
	output.OrgGuardrailRisks = input.OrgGuardrailRisks
	output.LambdaConfigRisks = input.LambdaConfigRisks
	output.EventWorkflowRisks = input.EventWorkflowRisks
	output.CacheSecurityRisks = input.CacheSecurityRisks
	output.RedshiftSecurityRisks = input.RedshiftSecurityRisks

	return output
}
