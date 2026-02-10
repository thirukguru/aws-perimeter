package model

// Flags represents the command line flags (minimal security-focused version).
type Flags struct {
	Profile       string
	Region        string
	Regions       []string
	AllRegions    bool
	OrgScan       bool
	Version       bool
	Output        string
	OutputFile    string
	Store         bool
	DBPath        string
	Trends        bool
	TrendDays     int
	Compare       bool
	ExportJSON    string
	ExportCSV     string
	DryRun        bool
	Remediate     bool
	DashboardPort int
	ConfigPath    string
}
