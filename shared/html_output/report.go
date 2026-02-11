// Package htmloutput provides HTML report generation for aws-perimeter.
package htmloutput

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// ReportData contains all data needed for HTML report generation
type ReportData struct {
	AccountID   string
	Region      string
	GeneratedAt string
	Sections    []Section
	Summary     Summary
}

// Summary contains security summary statistics
type Summary struct {
	TotalFindings    int
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	SecurityScore    int
	ScoreDescription string
}

// Section represents a collapsible section in the report
type Section struct {
	ID          string
	Title       string
	Description string
	Findings    []Finding
	Status      string // "critical", "warning", "good"
}

// Finding represents an individual security finding
type Finding struct {
	Severity       string
	Title          string
	Resource       string
	Description    string
	Recommendation string
	Compliance     []string // CIS, NIST, PCI-DSS control IDs
}

// GenerateHTMLReport generates a complete HTML report from the provided data
func GenerateHTMLReport(data ReportData) (string, error) {
	if data.GeneratedAt == "" {
		data.GeneratedAt = time.Now().Format("2006-01-02 15:04:05 MST")
	}

	// Calculate summary if not provided
	if data.Summary.TotalFindings == 0 {
		for _, section := range data.Sections {
			for _, finding := range section.Findings {
				data.Summary.TotalFindings++
				switch finding.Severity {
				case "CRITICAL":
					data.Summary.CriticalCount++
				case "HIGH":
					data.Summary.HighCount++
				case "MEDIUM":
					data.Summary.MediumCount++
				case "LOW":
					data.Summary.LowCount++
				}
			}
		}
	}

	// Calculate security score (100 - weighted penalties)
	score := 100
	score -= data.Summary.CriticalCount * 15
	score -= data.Summary.HighCount * 8
	score -= data.Summary.MediumCount * 3
	score -= data.Summary.LowCount * 1
	if score < 0 {
		score = 0
	}
	data.Summary.SecurityScore = score

	switch {
	case score >= 90:
		data.Summary.ScoreDescription = "Excellent"
	case score >= 70:
		data.Summary.ScoreDescription = "Good"
	case score >= 50:
		data.Summary.ScoreDescription = "Needs Improvement"
	default:
		data.Summary.ScoreDescription = "Critical"
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": func(s string) string {
			return strings.ToLower(s)
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// SeverityClass returns a CSS class based on severity
func SeverityClass(severity string) string {
	switch severity {
	case "CRITICAL":
		return "severity-critical"
	case "HIGH":
		return "severity-high"
	case "MEDIUM":
		return "severity-medium"
	case "LOW":
		return "severity-low"
	default:
		return "severity-info"
	}
}
