// Package main is the entry point for the aws-perimeter application.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/flag"
	"github.com/thirukguru/aws-perimeter/service/orchestrator"
	"github.com/thirukguru/aws-perimeter/service/output"
	"github.com/thirukguru/aws-perimeter/service/storage"
	"github.com/thirukguru/aws-perimeter/shared/banner"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "db", "history", "dashboard":
			return runStorageCommand(os.Args[1], os.Args[2:])
		}
	}

	flagService := flag.NewService()
	flags, err := flagService.GetParsedFlags()
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	versionInfo := model.VersionInfo{Version: version, Commit: commit, Date: date}

	if flags.Rules || flags.Capabilities {
		if err := printRequestedDocs(flags); err != nil {
			return err
		}
		return nil
	}

	if flags.Version {
		outputService := output.NewService(flags.Output)
		orchestratorService := orchestrator.NewService(
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			outputService, versionInfo,
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			nil, nil,
			nil,
			nil,
			nil,
			nil,
		)
		return orchestratorService.Orchestrate(flags)
	}

	if flags.Output != "json" {
		banner.DrawBannerTitle()
	}

	var storageService storage.Service
	if flags.Store || flags.Trends || flags.Compare || flags.ExportJSON != "" || flags.ExportCSV != "" {
		storageService, err = storage.NewService(flags.DBPath)
		if err != nil {
			return fmt.Errorf("failed to initialize storage: %w", err)
		}
		defer storageService.Close()
	}

	if flags.Trends {
		if storageService == nil {
			return fmt.Errorf("--trends requires initialized storage")
		}
		accountID := flags.AccountID
		if accountID == "" {
			accountID, err = getAccountIDForFlags(flags)
			if err != nil {
				return fmt.Errorf("failed to get account ID for trends: %w", err)
			}
		}
		return runTrendWorkflow(storageService, struct {
			TrendDays  int
			Compare    bool
			ExportJSON string
			ExportCSV  string
			AccountID  string
		}{
			TrendDays:  flags.TrendDays,
			Compare:    flags.Compare,
			ExportJSON: flags.ExportJSON,
			ExportCSV:  flags.ExportCSV,
			AccountID:  accountID,
		})
	}

	if flags.OrgScan {
		return runOrgScans(flags, versionInfo, storageService)
	}

	if flags.AllRegions || len(flags.Regions) > 0 {
		return runMultiRegionScans(flags, versionInfo, storageService)
	}

	return runRegionScan(flags, versionInfo, storageService)
}

func printRequestedDocs(flags model.Flags) error {
	type docSpec struct {
		enabled bool
		path    string
		label   string
	}
	docs := []docSpec{
		{enabled: flags.Rules, path: "RULES.md", label: "--rules"},
		{enabled: flags.Capabilities, path: "docs/CAPABILITIES_OVERVIEW.md", label: "--capabilities"},
	}

	printed := 0
	for _, d := range docs {
		if !d.enabled {
			continue
		}
		content, err := os.ReadFile(d.path)
		if err != nil {
			return fmt.Errorf("%s failed: unable to read %s: %w", d.label, d.path, err)
		}
		text := strings.TrimSpace(string(content))
		if text == "" {
			return fmt.Errorf("%s failed: %s is empty", d.label, d.path)
		}
		if printed > 0 {
			fmt.Println()
			fmt.Println("---")
			fmt.Println()
		}
		fmt.Println(text)
		printed++
	}

	return nil
}
