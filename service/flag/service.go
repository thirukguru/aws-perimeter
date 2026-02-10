package flag

import (
	"strings"

	"github.com/spf13/pflag"
	"github.com/thirukguru/aws-perimeter/model"
)

// NewService creates a new flag service.
func NewService() Service {
	return &service{}
}

// GetParsedFlags parses and returns the command-line flags.
func (s *service) GetParsedFlags() (model.Flags, error) {
	profile := pflag.StringP("profile", "p", "", "AWS profile to use")
	region := pflag.StringP("region", "r", "", "AWS region to use")
	regions := pflag.String("regions", "", "Comma-separated AWS regions to scan")
	allRegions := pflag.Bool("all-regions", false, "Scan all enabled AWS regions")
	orgScan := pflag.Bool("org-scan", false, "Scan all organization accounts (management account required)")
	version := pflag.BoolP("version", "v", false, "Show version information")
	output := pflag.StringP("output", "o", "table", "Output format (table, json, or html)")
	outputFile := pflag.StringP("output-file", "f", "", "Output file path (required for html format)")
	store := pflag.Bool("store", false, "Persist scan results in local SQLite database")
	dbPath := pflag.String("db-path", "", "Custom SQLite database path (default ~/.aws-perimeter/history.db)")
	trends := pflag.Bool("trends", false, "Show historical trends from stored scans")
	trendDays := pflag.Int("trend-days", 30, "Number of days for trend analysis")
	compare := pflag.Bool("compare", false, "Compare two most recent scans")
	exportJSON := pflag.String("export-json", "", "Export trend output as JSON to file path")
	exportCSV := pflag.String("export-csv", "", "Export trend output as CSV to file path")
	dryRun := pflag.Bool("dry-run", false, "Preview remediation actions without applying changes")
	remediate := pflag.Bool("remediate", false, "Apply supported automated remediations")
	dashboardPort := pflag.Int("dashboard-port", 8080, "Port for local dashboard server")
	configPath := pflag.String("config-path", "", "Path to aws-perimeter config file")

	pflag.Parse()

	var parsedRegions []string
	if *regions != "" {
		for _, r := range strings.Split(*regions, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				parsedRegions = append(parsedRegions, r)
			}
		}
	}

	flags := model.Flags{
		Profile:       *profile,
		Region:        *region,
		Regions:       parsedRegions,
		AllRegions:    *allRegions,
		OrgScan:       *orgScan,
		Version:       *version,
		Output:        *output,
		OutputFile:    *outputFile,
		Store:         *store,
		DBPath:        *dbPath,
		Trends:        *trends,
		TrendDays:     *trendDays,
		Compare:       *compare,
		ExportJSON:    *exportJSON,
		ExportCSV:     *exportCSV,
		DryRun:        *dryRun,
		Remediate:     *remediate,
		DashboardPort: *dashboardPort,
		ConfigPath:    *configPath,
	}

	return flags, nil
}
