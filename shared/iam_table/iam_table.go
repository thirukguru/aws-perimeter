// Package iamtable provides utilities for rendering IAM security findings in a table format.
package iamtable

import (
	"fmt"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/iam"
)

// DrawIAMTable renders the IAM security findings in a formatted table.
func DrawIAMTable(input model.RenderIAMInput) {
	fmt.Printf("\n🔑 IAM Security Report - Account: %s\n", input.AccountID)

	totalFindings := len(input.PrivilegeEscalation) + len(input.StaleCredentials) +
		len(input.CrossAccountTrusts) + len(input.UsersWithoutMFA) + len(input.OverlyPermissivePolicies)

	if totalFindings == 0 {
		fmt.Println(text.FgGreen.Sprint("\n✅ No IAM security issues found!"))
		return
	}

	// Privilege Escalation Risks
	if len(input.PrivilegeEscalation) > 0 {
		drawPrivEscTable(input.PrivilegeEscalation)
	}

	// Stale Credentials
	if len(input.StaleCredentials) > 0 {
		drawStaleCredentialsTable(input.StaleCredentials)
	}

	// Cross-Account Trusts
	if len(input.CrossAccountTrusts) > 0 {
		drawCrossAccountTable(input.CrossAccountTrusts)
	}

	// Users Without MFA
	if len(input.UsersWithoutMFA) > 0 {
		drawMFATable(input.UsersWithoutMFA)
	}

	// Overly Permissive Policies
	if len(input.OverlyPermissivePolicies) > 0 {
		drawDangerousPoliciesTable(input.OverlyPermissivePolicies)
	}
}

func drawPrivEscTable(risks []iam.PrivEscRisk) {
	fmt.Println("\n" + text.FgRed.Sprint("🚨 Privilege Escalation Risks"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Severity", "Type", "Principal", "Escalation Path", "Dangerous Actions"})

	for _, r := range risks {
		severity := formatSeverity(r.Severity)
		actionsDisplay := strings.Join(r.DangerousActions, ", ")
		if len(actionsDisplay) > 40 {
			actionsDisplay = actionsDisplay[:37] + "..."
		}

		t.AppendRow(table.Row{
			severity,
			r.PrincipalType,
			r.PrincipalName,
			truncate(r.EscalationPath, 35),
			actionsDisplay,
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawStaleCredentialsTable(creds []iam.StaleCredential) {
	fmt.Println("\n" + text.FgYellow.Sprint("🔑 Stale Credentials"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Severity", "User", "Type", "Key ID", "Created", "Last Used", "Age (days)"})

	for _, c := range creds {
		severity := formatSeverity(c.Severity)
		keyID := c.AccessKeyID
		if len(keyID) > 10 {
			keyID = keyID[:10] + "..."
		}

		t.AppendRow(table.Row{
			severity,
			c.UserName,
			c.CredentialType,
			keyID,
			c.CreatedDate,
			c.LastUsedDate,
			c.DaysSinceCreation,
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawCrossAccountTable(trusts []iam.CrossAccountTrust) {
	fmt.Println("\n" + text.FgRed.Sprint("🌐 Cross-Account Trust Risks"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Severity", "Role", "Trusted Account", "Description"})

	for _, tr := range trusts {
		severity := formatSeverity(tr.Severity)
		trusted := tr.TrustedAccountID
		if tr.AllowsAnyPrincipal {
			trusted = text.FgRed.Sprint("ANY (*)")
		}

		t.AppendRow(table.Row{
			severity,
			tr.RoleName,
			trusted,
			truncate(tr.Description, 45),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawMFATable(users []iam.UserMFAStatus) {
	fmt.Println("\n" + text.FgYellow.Sprint("🔓 Console Users Without MFA"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Severity", "User", "Console Access", "MFA Enabled", "Recommendation"})

	for _, u := range users {
		severity := formatSeverity(u.Severity)
		console := "Yes"
		mfa := text.FgRed.Sprint("No")

		t.AppendRow(table.Row{
			severity,
			u.UserName,
			console,
			mfa,
			u.Recommendation,
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawDangerousPoliciesTable(policies []iam.DangerousPolicy) {
	fmt.Println("\n" + text.FgRed.Sprint("⚠️ Overly Permissive Policies"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Severity", "Policy Name", "Type", "Reason"})

	for _, p := range policies {
		severity := formatSeverity(p.Severity)
		reason := "Full admin access (*:*)"
		if len(p.DangerousStmts) > 0 {
			reason = p.DangerousStmts[0].Reason
		}

		t.AppendRow(table.Row{
			severity,
			p.PolicyName,
			p.PolicyType,
			truncate(reason, 40),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func formatSeverity(severity string) string {
	switch severity {
	case iam.SeverityCritical:
		return text.FgRed.Sprint("🔴 CRITICAL")
	case iam.SeverityHigh:
		return text.FgHiRed.Sprint("🟠 HIGH")
	case iam.SeverityMedium:
		return text.FgYellow.Sprint("🟡 MEDIUM")
	case iam.SeverityLow:
		return text.FgCyan.Sprint("🔵 LOW")
	case iam.SeverityInfo:
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
