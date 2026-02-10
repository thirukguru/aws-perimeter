// Package extratables provides table renderers for extended security checks.
package extratables

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/thirukguru/aws-perimeter/service/cloudtrailsecurity"
	"github.com/thirukguru/aws-perimeter/service/config"
	"github.com/thirukguru/aws-perimeter/service/dataprotection"
	"github.com/thirukguru/aws-perimeter/service/elb"
	"github.com/thirukguru/aws-perimeter/service/iamadvanced"
	"github.com/thirukguru/aws-perimeter/service/lambdasecurity"
	"github.com/thirukguru/aws-perimeter/service/shield"
	"github.com/thirukguru/aws-perimeter/service/vpcadvanced"
	"github.com/thirukguru/aws-perimeter/service/vpcendpoints"
)

// ExtendedSecurityInput holds all extended service findings
type ExtendedSecurityInput struct {
	AccountID string
	Region    string
	// Shield/WAF
	ShieldStatus *shield.DDoSProtectionStatus
	WAFStatus    []shield.WAFStatus
	// ELB
	ALBRisks      []elb.ALBSecurityRisk
	ListenerRisks []elb.ListenerSecurityRisk
	// Lambda Security
	LambdaRoles    []lambdasecurity.OverlyPermissiveRole
	LambdaCrossReg []lambdasecurity.CrossRegionExecution
	// CloudTrail Security
	RoleCreations []cloudtrailsecurity.IAMRoleCreationEvent
	RootUsage     []cloudtrailsecurity.RootAccountUsage
	// Config/KMS
	ConfigStatus  *config.ConfigStatus
	EBSEncryption *config.EBSEncryptionStatus
	KMSRotation   []config.KMSKeyRotation
	// Data Protection
	RDSRisks     []dataprotection.RDSSecurityRisk
	DynamoRisks  []dataprotection.DynamoDBRisk
	SecretRisks  []dataprotection.SecretRotationRisk
	BackupStatus *dataprotection.BackupStatus
	// VPC Endpoints
	EndpointStatus   *vpcendpoints.EndpointStatus
	EndpointRisks    []vpcendpoints.EndpointRisk
	NATStatus        *vpcendpoints.NATGatewayStatus
	MissingEndpoints []vpcendpoints.MissingEndpoint
	// VPC Advanced
	PeeringRisks   []vpcadvanced.VPCPeeringRisk
	BastionHosts   []vpcadvanced.BastionHost
	SubnetClass    []vpcadvanced.SubnetClassification
	AZDistribution []vpcadvanced.AZDistribution
	// IAM Advanced
	RoleChainRisks   []iamadvanced.RoleChainRisk
	ExternalIDRisks  []iamadvanced.ExternalIDRisk
	BoundaryRisks    []iamadvanced.PermissionBoundaryRisk
	InstanceProfiles []iamadvanced.InstanceProfileRisk
}

// DrawExtendedSecurityTable renders all extended security findings
func DrawExtendedSecurityTable(input ExtendedSecurityInput) {
	fmt.Printf("\n🔒 Extended Security Report - Account: %s\n", input.AccountID)

	// === Shield/WAF Section ===
	if input.ShieldStatus != nil {
		if input.ShieldStatus.ShieldAdvancedEnabled {
			fmt.Println("\n" + text.FgGreen.Sprint("✅ Shield Advanced: Enabled"))
		} else {
			fmt.Println("\n" + text.FgYellow.Sprint("⚠️ Shield: Standard only"))
		}
	}

	// === VPC Endpoints Section ===
	if input.EndpointStatus != nil {
		fmt.Println("\n" + text.FgCyan.Sprint("🔗 VPC Endpoints"))
		fmt.Printf("   Gateway: %d, Interface: %d", input.EndpointStatus.GatewayEndpoints, input.EndpointStatus.InterfaceEndpoints)
		if !input.EndpointStatus.S3EndpointExists {
			fmt.Print(" " + text.FgYellow.Sprint("(Missing S3)"))
		}
		fmt.Println()
	}

	if len(input.MissingEndpoints) > 0 {
		fmt.Println("\n" + text.FgYellow.Sprint("⚠️ Recommended VPC Endpoints"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Service", "Reason"})
		for _, e := range input.MissingEndpoints {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(e.Severity), e.ServiceName, truncate(e.TrafficType, 40)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// === NAT Security ===
	if input.NATStatus != nil && (input.NATStatus.NATGatewayCount > 0 || input.NATStatus.NATInstanceCount > 0) {
		fmt.Println("\n" + text.FgCyan.Sprint("🌐 NAT Configuration"))
		fmt.Printf("   NAT Gateways: %d, NAT Instances: %d\n", input.NATStatus.NATGatewayCount, input.NATStatus.NATInstanceCount)
		if input.NATStatus.SingleAZRisk {
			fmt.Println("   " + text.FgYellow.Sprint("⚠️ Single-AZ risk detected"))
		}
	}

	// === VPC Peering ===
	if len(input.PeeringRisks) > 0 {
		fmt.Println("\n" + text.FgCyan.Sprint("🔀 VPC Peering Connections"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Peering ID", "Cross-Account", "Cross-Region"})
		for _, p := range input.PeeringRisks {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(p.Severity), p.PeeringID, boolIcon(p.IsCrossAccount), boolIcon(p.IsCrossRegion)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// === Bastion Hosts ===
	if len(input.BastionHosts) > 0 {
		fmt.Println("\n" + text.FgYellow.Sprint("🏰 Bastion/Jump Hosts"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Instance", "Public IP", "SSH", "RDP"})
		for _, b := range input.BastionHosts {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(b.Severity), b.InstanceID, b.PublicIP, boolIcon(b.SSHPort), boolIcon(b.RDPPort)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// === Config/EBS/KMS ===
	if input.ConfigStatus != nil {
		status := text.FgGreen.Sprint("✅ Enabled")
		if !input.ConfigStatus.IsEnabled {
			status = text.FgRed.Sprint("❌ Not Enabled")
		}
		fmt.Printf("\n📋 AWS Config: %s\n", status)
	}

	if input.EBSEncryption != nil && !input.EBSEncryption.DefaultEncryptionEnabled {
		fmt.Println(text.FgYellow.Sprint("⚠️ EBS default encryption: Not enabled"))
	}

	if len(input.KMSRotation) > 0 {
		var noRotation int
		for _, k := range input.KMSRotation {
			if !k.RotationEnabled {
				noRotation++
			}
		}
		if noRotation > 0 {
			fmt.Printf("%s %d KMS keys without rotation\n", text.FgYellow.Sprint("⚠️"), noRotation)
		}
	}

	// === Root Account Usage ===
	if len(input.RootUsage) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("🚨 Root Account Usage Detected!"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Event", "Source IP", "Time"})
		for _, r := range input.RootUsage {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(r.Severity), r.EventName, r.SourceIP, r.EventTime.Format("2006-01-02 15:04")})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// === IAM Advanced ===
	if len(input.ExternalIDRisks) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("⚠️ Cross-Account Roles Without External ID"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Role", "Trusted Account", "Has ExternalID"})
		for _, r := range input.ExternalIDRisks {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(r.Severity), truncate(r.RoleName, 25), r.TrustedAccount, boolIcon(r.HasExternalID)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	if len(input.BoundaryRisks) > 0 {
		fmt.Println("\n" + text.FgYellow.Sprint("📦 Missing Permission Boundaries"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Type", "Principal", "Policies"})
		for _, b := range input.BoundaryRisks {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(b.Severity), b.PrincipalType, truncate(b.PrincipalName, 25), b.AttachedPolicies})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// === Data Protection ===
	if len(input.RDSRisks) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("🗄️ RDS Security Issues"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "DB Instance", "Public", "Encrypted"})
		for _, r := range input.RDSRisks {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(r.Severity), r.DBInstanceID, boolIcon(r.IsPublic), boolIcon(r.IsEncrypted)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// === Lambda Security ===
	if len(input.LambdaRoles) > 0 {
		fmt.Println("\n" + text.FgRed.Sprint("λ Lambda Overly Permissive Roles"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "Function", "Role", "Description"})
		for _, l := range input.LambdaRoles {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(l.Severity), truncate(l.FunctionName, 20), truncate(l.RoleName, 20), truncate(l.Description, 30)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// === ELB Security ===
	if len(input.ALBRisks) > 0 {
		fmt.Println("\n" + text.FgYellow.Sprint("⚖️ ALB Security Issues"))
		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)
		t.AppendHeader(table.Row{"Account", "Region", "Severity", "ALB", "Risk Type", "Description"})
		for _, r := range input.ALBRisks {
			t.AppendRow(table.Row{input.AccountID, input.Region, formatSeverity(r.Severity), truncate(r.LoadBalancerName, 20), r.RiskType, truncate(r.Description, 30)})
		}
		t.SetStyle(table.StyleRounded)
		t.Render()
	}

	// === Summary ===
	totalIssues := countTotalIssues(input)
	if totalIssues == 0 {
		fmt.Println(text.FgGreen.Sprint("\n✅ Extended security checks passed!"))
	} else {
		fmt.Printf("\n📊 Total extended findings: %d\n", totalIssues)
	}
}

func boolIcon(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

func countTotalIssues(input ExtendedSecurityInput) int {
	return len(input.ALBRisks) + len(input.LambdaRoles) +
		len(input.RootUsage) + len(input.RDSRisks) + len(input.ExternalIDRisks) +
		len(input.BoundaryRisks) + len(input.PeeringRisks) + len(input.BastionHosts) +
		len(input.MissingEndpoints)
}
