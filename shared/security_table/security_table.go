// Package securitytable provides utilities for rendering security findings in a table format.
package securitytable

import (
	"fmt"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/vpc"
)

// DrawSecurityTable renders the security findings in a formatted table.
func DrawSecurityTable(input model.RenderSecurityInput) {
	// Summary
	criticalCount, highCount, mediumCount, lowCount, infoCount := countSeverities(input)
	totalFindings := criticalCount + highCount + mediumCount + lowCount + infoCount

	if totalFindings == 0 {
		return
	}

	fmt.Println("\n🔒 VPC Security")
	fmt.Printf("   ")
	if criticalCount > 0 {
		fmt.Printf("%s ", text.FgRed.Sprintf("🔴 %d Critical", criticalCount))
	}

	if highCount > 0 {
		fmt.Printf("%s ", text.FgHiRed.Sprintf("🟠 %d High", highCount))
	}

	if mediumCount > 0 {
		fmt.Printf("%s ", text.FgYellow.Sprintf("🟡 %d Medium", mediumCount))
	}

	if lowCount > 0 {
		fmt.Printf("%s ", text.FgCyan.Sprintf("🔵 %d Low", lowCount))
	}

	if infoCount > 0 {
		fmt.Printf("%s ", text.FgGreen.Sprintf("🟢 %d Info", infoCount))
	}

	fmt.Println()

	// Security Group Risks
	if len(input.SecurityGroupRisks) > 0 {
		drawSGRisksTable(input.AccountID, input.Region, input.SecurityGroupRisks)
	}

	// Public Exposure Risks
	if len(input.PublicExposureRisks) > 0 {
		drawExposureTable(input.AccountID, input.Region, input.PublicExposureRisks)
	}

	// NACL Risks
	if len(input.NACLRisks) > 0 {
		drawNACLTable(input.AccountID, input.Region, input.NACLRisks)
	}

	// VPC Flow Log Status
	drawFlowLogTable(input.AccountID, input.Region, input.VPCFlowLogStatus)

	// Unused Security Groups
	if len(input.UnusedSecurityGroups) > 0 {
		drawUnusedSGTable(input.AccountID, input.Region, input.UnusedSecurityGroups)
	}

	// Phase T: Nation-State Threat Detection
	if len(input.ManagementExposure) > 0 {
		drawManagementExposureTable(input.AccountID, input.Region, input.ManagementExposure)
	}

	if len(input.PlaintextRisks) > 0 {
		drawPlaintextRisksTable(input.AccountID, input.Region, input.PlaintextRisks)
	}

	if len(input.IMDSv1Risks) > 0 {
		drawIMDSv1Table(input.AccountID, input.Region, input.IMDSv1Risks)
	}
}

func countSeverities(input model.RenderSecurityInput) (critical, high, medium, low, info int) {
	for _, r := range input.SecurityGroupRisks {
		switch r.Severity {
		case vpc.SeverityCritical:
			critical++
		case vpc.SeverityHigh:
			high++
		case vpc.SeverityMedium:
			medium++
		case vpc.SeverityLow:
			low++
		case vpc.SeverityInfo:
			info++
		}
	}

	for _, r := range input.PublicExposureRisks {
		switch r.Severity {
		case vpc.SeverityCritical:
			critical++
		case vpc.SeverityHigh:
			high++
		case vpc.SeverityMedium:
			medium++
		}
	}

	for _, r := range input.NACLRisks {
		switch r.Severity {
		case vpc.SeverityMedium:
			medium++
		}
	}

	for _, s := range input.VPCFlowLogStatus {
		if !s.FlowLogsEnabled {
			medium++
		}
	}

	info += len(input.UnusedSecurityGroups)

	// Phase T: Nation-State Threat Detection
	for _, r := range input.ManagementExposure {
		switch r.Severity {
		case vpc.SeverityCritical:
			critical++
		case vpc.SeverityHigh:
			high++
		}
	}

	for _, r := range input.PlaintextRisks {
		switch r.Severity {
		case vpc.SeverityCritical:
			critical++
		case vpc.SeverityHigh:
			high++
		}
	}

	for _, r := range input.IMDSv1Risks {
		switch r.Severity {
		case vpc.SeverityCritical:
			critical++
		case vpc.SeverityHigh:
			high++
		}
	}

	return
}

func drawSGRisksTable(accountID, region string, risks []vpc.SGRisk) {
	fmt.Println("\n" + text.FgRed.Sprint("🚨 Security Group Risks"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "Severity", "Security Group", "Risk Type", "Port", "Source CIDR", "Recommendation"})

	for _, r := range risks {
		severity := formatSeverity(r.Severity)
		sgDisplay := fmt.Sprintf("%s\n%s", r.SecurityGroupName, r.SecurityGroupID)
		portDisplay := fmt.Sprintf("%d", r.Port)

		if r.Port < 0 {
			portDisplay = "ALL"
		}

		t.AppendRow(table.Row{
			accountID,
			region,
			severity,
			sgDisplay,
			r.RiskType,
			portDisplay,
			r.SourceCIDR,
			truncate(r.Recommendation, 40),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawExposureTable(accountID, region string, risks []vpc.ExposureRisk) {
	fmt.Println("\n" + text.FgRed.Sprint("🌐 Public Exposure Risks"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "Severity", "Instance", "Public IP", "Open Ports", "Recommendation"})

	for _, r := range risks {
		severity := formatSeverity(r.Severity)
		instanceDisplay := r.InstanceID
		if r.InstanceName != "" {
			instanceDisplay = fmt.Sprintf("%s\n%s", r.InstanceName, r.InstanceID)
		}

		var ports []string
		for _, p := range r.OpenPorts {
			ports = append(ports, fmt.Sprintf("%d", p))
		}

		t.AppendRow(table.Row{
			accountID,
			region,
			severity,
			instanceDisplay,
			r.PublicIP,
			strings.Join(ports, ", "),
			truncate(r.Recommendation, 40),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawNACLTable(accountID, region string, risks []vpc.NACLRisk) {
	fmt.Println("\n" + text.FgYellow.Sprint("🔒 Network ACL Risks"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "Severity", "NACL ID", "Rule #", "Protocol", "CIDR", "Description"})

	for _, r := range risks {
		severity := formatSeverity(r.Severity)
		t.AppendRow(table.Row{
			accountID,
			region,
			severity,
			r.NetworkAclID,
			r.RuleNumber,
			r.Protocol,
			r.CidrBlock,
			r.Description,
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawFlowLogTable(accountID, region string, statuses []vpc.FlowLogStatus) {
	fmt.Println("\n" + text.FgCyan.Sprint("📊 VPC Flow Log Status"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "VPC", "Flow Logs Enabled", "Recommendation"})

	for _, s := range statuses {
		vpcDisplay := s.VpcID
		if s.VpcName != "" {
			vpcDisplay = fmt.Sprintf("%s (%s)", s.VpcName, s.VpcID)
		}

		enabledDisplay := text.FgGreen.Sprint("✅ Yes")
		recommendation := "-"

		if !s.FlowLogsEnabled {
			enabledDisplay = text.FgYellow.Sprint("❌ No")
			recommendation = s.Recommendation
		}

		t.AppendRow(table.Row{
			accountID,
			region,
			vpcDisplay,
			enabledDisplay,
			truncate(recommendation, 50),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawUnusedSGTable(accountID, region string, unused []vpc.UnusedSG) {
	fmt.Println("\n" + text.FgGreen.Sprint("🗑️ Unused Security Groups (cleanup candidates)"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "Security Group ID", "Name", "VPC ID", "Description"})

	for _, sg := range unused {
		t.AppendRow(table.Row{
			accountID,
			region,
			sg.SecurityGroupID,
			sg.SecurityGroupName,
			sg.VpcID,
			truncate(sg.Description, 40),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func formatSeverity(severity string) string {
	switch severity {
	case vpc.SeverityCritical:
		return text.FgRed.Sprint("🔴 CRITICAL")
	case vpc.SeverityHigh:
		return text.FgHiRed.Sprint("🟠 HIGH")
	case vpc.SeverityMedium:
		return text.FgYellow.Sprint("🟡 MEDIUM")
	case vpc.SeverityLow:
		return text.FgCyan.Sprint("🔵 LOW")
	case vpc.SeverityInfo:
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

// Phase T: Nation-State Threat Detection Tables

func drawManagementExposureTable(accountID, region string, risks []vpc.ManagementExposure) {
	fmt.Println("\n" + text.FgRed.Sprint("⚠️  NATION-STATE THREAT: Management Interface Exposure"))
	fmt.Println(text.FgHiBlack.Sprint("   Based on AWS Threat Intel - GRU Sandworm campaign targeting network edge devices"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "Severity", "Instance", "Public IP", "Exposed Ports", "Recommendation"})

	for _, r := range risks {
		severity := formatSeverity(r.Severity)
		instanceDisplay := r.InstanceID
		if r.InstanceName != "" && r.InstanceName != r.InstanceID {
			instanceDisplay = fmt.Sprintf("%s\n%s", r.InstanceName, r.InstanceID)
		}

		var ports []string
		for _, p := range r.ExposedPorts {
			ports = append(ports, fmt.Sprintf("%d", p))
		}

		t.AppendRow(table.Row{
			accountID,
			region,
			severity,
			instanceDisplay,
			r.PublicIP,
			strings.Join(ports, ", "),
			truncate(r.Recommendation, 50),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawPlaintextRisksTable(accountID, region string, risks []vpc.PlaintextRisk) {
	fmt.Println("\n" + text.FgRed.Sprint("⚠️  NATION-STATE THREAT: Plaintext Protocol Exposure"))
	fmt.Println(text.FgHiBlack.Sprint("   Based on AWS Threat Intel - credential harvesting via traffic interception"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "Severity", "Security Group", "Protocol", "Port", "Source CIDR", "Recommendation"})

	for _, r := range risks {
		severity := formatSeverity(r.Severity)
		sgDisplay := fmt.Sprintf("%s\n%s", r.SecurityGroupName, r.SecurityGroupID)

		t.AppendRow(table.Row{
			accountID,
			region,
			severity,
			sgDisplay,
			r.Protocol,
			r.Port,
			r.SourceCIDR,
			truncate(r.Recommendation, 50),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}

func drawIMDSv1Table(accountID, region string, risks []vpc.IMDSv1Risk) {
	fmt.Println("\n" + text.FgHiRed.Sprint("⚠️  CREDENTIAL THEFT RISK: IMDSv1 Enabled"))
	fmt.Println(text.FgHiBlack.Sprint("   IMDSv1 allows SSRF attacks to steal instance credentials"))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "Severity", "Instance", "IMDSv1", "Recommendation"})

	for _, r := range risks {
		severity := formatSeverity(r.Severity)
		instanceDisplay := r.InstanceID
		if r.InstanceName != "" && r.InstanceName != r.InstanceID {
			instanceDisplay = fmt.Sprintf("%s\n%s", r.InstanceName, r.InstanceID)
		}

		imdsStatus := text.FgRed.Sprint("ENABLED")

		t.AppendRow(table.Row{
			accountID,
			region,
			severity,
			instanceDisplay,
			imdsStatus,
			truncate(r.Recommendation, 50),
		})
	}

	t.SetStyle(table.StyleRounded)
	t.Render()
}
