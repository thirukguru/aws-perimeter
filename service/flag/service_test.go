package flag

import (
	"os"
	"testing"

	"github.com/spf13/pflag"
)

func resetFlagState(t *testing.T, args []string) func() {
	t.Helper()
	oldCommandLine := pflag.CommandLine
	oldArgs := os.Args
	pflag.CommandLine = pflag.NewFlagSet("test", pflag.ContinueOnError)
	os.Args = append([]string{"aws-perimeter"}, args...)
	return func() {
		pflag.CommandLine = oldCommandLine
		os.Args = oldArgs
	}
}

func TestGetParsedFlagsAllNewOptions(t *testing.T) {
	cleanup := resetFlagState(t, []string{
		"--profile", "prod",
		"--region", "us-east-1",
		"--regions", "us-east-1, us-west-2",
		"--all-regions",
		"--org-scan",
		"--org-role-name", "AuditRole",
		"--external-id", "ext-123",
		"--rules",
		"--capabilities",
		"--output", "json",
		"--output-file", "report.html",
		"--store",
		"--db-path", "/tmp/history.db",
		"--trends",
		"--trend-days", "15",
		"--compare",
		"--export-json", "out.json",
		"--export-csv", "out.csv",
		"--account-id", "123456789012",
		"--max-parallel", "7",
		"--best-effort",
		"--dry-run",
		"--remediate",
		"--dashboard-port", "9090",
		"--config-path", "/tmp/config.yaml",
	})
	defer cleanup()

	svc := NewService()
	flags, err := svc.GetParsedFlags()
	if err != nil {
		t.Fatalf("GetParsedFlags failed: %v", err)
	}

	if flags.Profile != "prod" || flags.Region != "us-east-1" {
		t.Fatalf("unexpected profile/region: %+v", flags)
	}
	if len(flags.Regions) != 2 || flags.Regions[0] != "us-east-1" || flags.Regions[1] != "us-west-2" {
		t.Fatalf("unexpected regions: %v", flags.Regions)
	}
	if !flags.AllRegions || !flags.OrgScan || flags.OrgRoleName != "AuditRole" || flags.ExternalID != "ext-123" {
		t.Fatalf("unexpected org flags: %+v", flags)
	}
	if !flags.Rules || !flags.Capabilities {
		t.Fatalf("unexpected docs flags: %+v", flags)
	}
	if !flags.Store || !flags.Trends || flags.TrendDays != 15 || !flags.Compare {
		t.Fatalf("unexpected storage/trend flags: %+v", flags)
	}
	if flags.ExportJSON != "out.json" || flags.ExportCSV != "out.csv" {
		t.Fatalf("unexpected export flags: %+v", flags)
	}
	if flags.AccountID != "123456789012" || flags.MaxParallel != 7 {
		t.Fatalf("unexpected account/parallel flags: %+v", flags)
	}
	if !flags.BestEffort {
		t.Fatalf("expected best-effort to be true: %+v", flags)
	}
	if !flags.DryRun || !flags.Remediate || flags.DashboardPort != 9090 || flags.ConfigPath != "/tmp/config.yaml" {
		t.Fatalf("unexpected remediation/config flags: %+v", flags)
	}
}

func TestGetParsedFlagsDefaults(t *testing.T) {
	cleanup := resetFlagState(t, nil)
	defer cleanup()

	svc := NewService()
	flags, err := svc.GetParsedFlags()
	if err != nil {
		t.Fatalf("GetParsedFlags failed: %v", err)
	}

	if flags.Output != "table" || flags.TrendDays != 30 || flags.DashboardPort != 8080 {
		t.Fatalf("unexpected defaults: %+v", flags)
	}
	if flags.OrgRoleName != "OrganizationAccountAccessRole" {
		t.Fatalf("unexpected default org role: %s", flags.OrgRoleName)
	}
	if flags.MaxParallel != 3 {
		t.Fatalf("unexpected max-parallel default: %d", flags.MaxParallel)
	}
	if flags.Rules || flags.Capabilities {
		t.Fatalf("unexpected docs flags default: %+v", flags)
	}
	if flags.BestEffort {
		t.Fatalf("unexpected best-effort default: %+v", flags)
	}
}
