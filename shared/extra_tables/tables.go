// Package extratables provides table renderers for S3, CloudTrail, Secrets, and Advanced checks.
package extratables

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/cloudtrail"
)

// DrawS3Table renders S3 security findings
func DrawS3Table(input model.RenderS3Input) {
	fmt.Printf("\n🪣 S3 Security Report - Account: %s\n", input.AccountID)

	total := len(input.PublicBuckets) + len(input.UnencryptedBkts) + len(input.RiskyPolicies)
	total += len(input.SensitiveExposures)
	if total == 0 {
		fmt.Println(text.FgGreen.Sprint("\n✅ No S3 security issues found!"))
		return
	}

	if len(input.PublicBuckets) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("🌐 Public/Unblocked Buckets"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Bucket", "Risk", "Recommendation"})
		for _, b := range input.PublicBuckets {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(b.Severity), b.BucketName, b.RiskType, truncate(b.Recommendation, 35)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.UnencryptedBkts) > 0 {
		fmt.Println("\n" + text.FgYellow.Sprint("🔓 Unencrypted Buckets"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Bucket", "Encryption", "Recommendation"})
		for _, b := range input.UnencryptedBkts {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(b.Severity), b.BucketName, b.EncryptionType, b.Recommendation})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.RiskyPolicies) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("⚠️ Risky Bucket Policies"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Bucket", "Public?", "Any Action?", "Recommendation"})
		for _, p := range input.RiskyPolicies {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(p.Severity), p.BucketName, p.AllowsPublic, p.AllowsAnyAction, p.Recommendation})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.SensitiveExposures) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("🧪 Sensitive File/Content Exposure"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Bucket", "Object", "Type", "Public", "Recommendation"})
		for _, e := range input.SensitiveExposures {
			publicStr := "No"
			if e.IsPublic {
				publicStr = "Yes"
			}
			t.AppendRow(table.Row{
				input.AccountID,
				input.Region,
				formatSeverity(e.Severity),
				e.BucketName,
				truncate(e.FileName, 30),
				e.FileType,
				publicStr,
				truncate(e.Recommendation, 35),
			})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}
}

// DrawCloudTrailTable renders CloudTrail findings
func DrawCloudTrailTable(input model.RenderCloudTrailInput) {
	fmt.Printf("\n📋 CloudTrail Report - Account: %s\n", input.AccountID)

	if len(input.TrailGaps) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("⚠️ CloudTrail Gaps"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Issue", "Description", "Recommendation"})
		for _, g := range input.TrailGaps {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(g.Severity), g.Issue, truncate(g.Description, 30), truncate(g.Recommendation, 35)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.TrailStatus) > 0 {
		fmt.Println("\n" + text.FgCyan.Sprint("📊 Trail Status"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Status", "Trail", "Multi-Region", "Logging", "Validation"})
		for _, s := range input.TrailStatus {
			logging := "❌"
			if s.IsLogging {
				logging = "✅"
			}
			multiRegion := "❌"
			if s.IsMultiRegion {
				multiRegion = "✅"
			}
			validation := "❌"
			if s.HasLogValidation {
				validation = "✅"
			}
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(s.Severity), s.TrailName, multiRegion, logging, validation})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.TrailGaps) == 0 && allTrailsHealthy(input.TrailStatus) {
		fmt.Println(text.FgGreen.Sprint("\n✅ CloudTrail is properly configured!"))
	}
}

// DrawSecretsTable renders secrets detection findings
func DrawSecretsTable(input model.RenderSecretsInput) {
	fmt.Printf("\n🔐 Secrets Detection Report - Account: %s\n", input.AccountID)

	total := len(input.LambdaSecrets) + len(input.EC2Secrets) + len(input.S3Secrets) + len(input.ECRSecrets)
	if total == 0 {
		fmt.Println(text.FgGreen.Sprint("\n✅ No exposed secrets detected!"))
		return
	}

	fmt.Printf("\n%s Found %d potential secrets!\n", text.FgRed.Sprint("⚠️"), total)

	if len(input.LambdaSecrets) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("λ Lambda Environment Variables"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Function", "Secret Type", "Location", "Pattern"})
		for _, s := range input.LambdaSecrets {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(s.Severity), truncate(s.ResourceName, 20), s.SecretType, truncate(s.Location, 25), s.MatchedPattern})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.EC2Secrets) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("💻 EC2 User Data"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Instance", "Secret Type", "Recommendation"})
		for _, s := range input.EC2Secrets {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(s.Severity), s.ResourceName, s.SecretType, truncate(s.Recommendation, 40)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.S3Secrets) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("🪣 S3 Object Content"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Bucket/Object", "Secret Type", "Location", "Recommendation"})
		for _, s := range input.S3Secrets {
			resource := s.ResourceName
			if resource == "" {
				resource = s.ResourceID
			}
			t.AppendRow(table.Row{
				input.AccountID,
				input.Region,
				formatSeverity(s.Severity),
				truncate(resource, 35),
				s.SecretType,
				truncate(s.Location, 25),
				truncate(s.Recommendation, 45),
			})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.ECRSecrets) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("🐳 ECR Image Layers"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Image", "Secret Type", "Location", "Recommendation"})
		for _, s := range input.ECRSecrets {
			resource := s.ResourceName
			if resource == "" {
				resource = s.ResourceID
			}
			t.AppendRow(table.Row{
				input.AccountID,
				input.Region,
				formatSeverity(s.Severity),
				truncate(resource, 35),
				s.SecretType,
				truncate(s.Location, 30),
				truncate(s.Recommendation, 45),
			})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}
}

// DrawAdvancedTable renders advanced security findings
func DrawAdvancedTable(input model.RenderAdvancedInput) {
	fmt.Printf("\n🛡️ Advanced Security Report - Account: %s\n", input.AccountID)

	// Security Hub
	if input.HubStatus != nil {
		if input.HubStatus.IsEnabled {
			fmt.Println("\n" + text.FgGreen.Sprint("✅ Security Hub: Enabled"))
		} else {
			fmt.Println("\n" + text.FgRed.Sprint("❌ Security Hub: Not Enabled"))
			fmt.Println(text.FgYellow.Sprint("   → " + input.HubStatus.Recommendation))
		}
	}

	if len(input.HubFindings) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("🚨 Security Hub Critical Findings"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Title", "Resource", "Compliance"})
		for _, f := range input.HubFindings {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(f.Severity), truncate(f.Title, 35), truncate(f.ResourceID, 25), f.Compliance})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// GuardDuty
	if input.GuardDutyStatus != nil {
		if input.GuardDutyStatus.IsEnabled {
			fmt.Println("\n" + text.FgGreen.Sprint("✅ GuardDuty: Enabled"))
		} else {
			fmt.Println("\n" + text.FgRed.Sprint("❌ GuardDuty: Not Enabled"))
			fmt.Println(text.FgYellow.Sprint("   → " + input.GuardDutyStatus.Recommendation))
		}
	}

	if len(input.GuardDutyFindings) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("⚔️ GuardDuty Threat Findings"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Type", "Resource", "Description"})
		for _, f := range input.GuardDutyFindings {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(f.SeverityLabel), truncate(f.Type, 30), f.ResourceID, truncate(f.Description, 35)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// API Gateway
	if len(input.APINoAuth) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("🔓 API Gateway Routes Without Authorization"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "API", "Route", "Recommendation"})
		for _, r := range input.APINoAuth {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(r.Severity), r.APIName, r.RouteKey, r.Recommendation})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.APINoRateLimits) > 0 {
		fmt.Println("\n" + text.FgYellow.Sprint("⚡ API Gateway Without Rate Limits"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "API", "Stage", "Recommendation"})
		for _, r := range input.APINoRateLimits {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(r.Severity), r.APIName, r.StageName, r.Recommendation})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// Resource-based Policies
	allPolicyRisks := append(input.LambdaPolicyRisks, input.SQSPolicyRisks...)
	allPolicyRisks = append(allPolicyRisks, input.SNSPolicyRisks...)

	if len(allPolicyRisks) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("📜 Resource-Based Policy Risks"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Type", "Resource", "Risk", "Condition?"})
		for _, r := range allPolicyRisks {
			hasCondStr := "❌"
			if r.HasCondition {
				hasCondStr = "✅"
			}
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(r.Severity), r.ResourceType, truncate(r.ResourceName, 20), r.RiskType, hasCondStr})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// Summary
	totalIssues := len(input.HubFindings) + len(input.GuardDutyFindings) +
		len(input.APINoAuth) + len(input.APINoRateLimits) + len(allPolicyRisks)

	if totalIssues == 0 &&
		(input.HubStatus == nil || input.HubStatus.IsEnabled) &&
		(input.GuardDutyStatus == nil || input.GuardDutyStatus.IsEnabled) {
		fmt.Println(text.FgGreen.Sprint("\n✅ Advanced security checks passed!"))
	}
}

func formatSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return text.FgRed.Sprint("🔴 CRITICAL")
	case "HIGH":
		return text.FgHiRed.Sprint("🟠 HIGH")
	case "MEDIUM":
		return text.FgYellow.Sprint("🟡 MEDIUM")
	case "LOW":
		return text.FgCyan.Sprint("🔵 LOW")
	case "INFO":
		return text.FgGreen.Sprint("🟢 INFO")
	default:
		return severity
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func allTrailsHealthy(trails []cloudtrail.TrailStatus) bool {
	for _, t := range trails {
		if t.Severity == "CRITICAL" || t.Severity == "HIGH" {
			return false
		}
	}
	return len(trails) > 0
}
