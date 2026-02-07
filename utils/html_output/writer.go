package htmloutput

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultReportDir is the default directory for HTML reports
const DefaultReportDir = "reports"

// WriteHTMLReport writes the HTML report to a file with datetime in filename
func WriteHTMLReport(outputPath string, data ReportData) error {
	html, err := GenerateHTMLReport(data)
	if err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}

	// Ensure the reports directory exists
	dir := filepath.Dir(outputPath)
	if dir == "" || dir == "." {
		dir = DefaultReportDir
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Generate filename with datetime if using default
	filename := filepath.Base(outputPath)
	if filename == outputPath || filename == "" {
		// No directory specified, use reports folder with datetime
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		filename = fmt.Sprintf("security-report_%s.html", timestamp)
		outputPath = filepath.Join(DefaultReportDir, filename)
	} else {
		// Use specified path but ensure it's in the reports dir if no dir specified
		outputPath = filepath.Join(dir, filename)
	}

	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}

	return nil
}

// GenerateReportPath generates a report path with datetime in the reports folder
func GenerateReportPath() string {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	return filepath.Join(DefaultReportDir, fmt.Sprintf("security-report_%s.html", timestamp))
}

// WriteHTMLString writes a pre-generated HTML string to a file
func WriteHTMLString(filepath string, html string) error {
	if err := os.WriteFile(filepath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}
	return nil
}
