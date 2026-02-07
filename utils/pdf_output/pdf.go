// Package pdfoutput provides PDF report generation for aws-perimeter.
package pdfoutput

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

// ReportData contains all data needed for PDF report generation
type ReportData struct {
	AccountID   string
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

// Section represents a section in the report
type Section struct {
	ID          string
	Title       string
	Description string
	Findings    []Finding
	Status      string
}

// Finding represents an individual security finding
type Finding struct {
	Severity       string
	Title          string
	Resource       string
	Description    string
	Recommendation string
	Compliance     []string
}

// GeneratePDFReport generates an HTML report optimized for PDF conversion
// The output can be converted to PDF using wkhtmltopdf or browser print
func GeneratePDFReport(data ReportData) (string, error) {
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

	// Calculate security score
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

	tmpl, err := template.New("pdf").Funcs(template.FuncMap{
		"lower": strings.ToLower,
		"join":  strings.Join,
	}).Parse(pdfTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse PDF template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute PDF template: %w", err)
	}

	return buf.String(), nil
}

// SavePDFReport saves the PDF-ready HTML to a file
func SavePDFReport(data ReportData, filepath string) error {
	html, err := GeneratePDFReport(data)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, []byte(html), 0644)
}

// PDF-optimized HTML template
const pdfTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AWS Security Report - {{.AccountID}}</title>
    <style>
        @page {
            size: A4;
            margin: 20mm;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Helvetica Neue', Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.5;
            color: #1a1a1a;
            background: white;
        }

        .header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 3px solid #232f3e;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 24pt;
            color: #232f3e;
            margin-bottom: 10px;
        }

        .header .meta {
            color: #666;
            font-size: 10pt;
        }

        .summary-grid {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
            gap: 15px;
        }

        .summary-card {
            flex: 1;
            text-align: center;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
        }

        .summary-card h3 {
            font-size: 9pt;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 8px;
        }

        .summary-card .value {
            font-size: 24pt;
            font-weight: bold;
        }

        .summary-card.critical .value { color: #d32f2f; }
        .summary-card.high .value { color: #ed6c02; }
        .summary-card.medium .value { color: #ffc107; }
        .summary-card.low .value { color: #2e7d32; }
        .summary-card.score .value { color: #1976d2; }

        .section {
            margin-bottom: 30px;
            page-break-inside: avoid;
        }

        .section-header {
            background: #232f3e;
            color: white;
            padding: 12px 20px;
            margin-bottom: 15px;
        }

        .section-header h2 {
            font-size: 14pt;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 10pt;
        }

        .findings-table th {
            background: #f5f5f5;
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
            font-weight: bold;
        }

        .findings-table td {
            padding: 10px;
            border: 1px solid #ddd;
            vertical-align: top;
        }

        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 9pt;
            font-weight: bold;
            text-transform: uppercase;
        }

        .severity-critical {
            background: #ffebee;
            color: #c62828;
            border: 1px solid #c62828;
        }

        .severity-high {
            background: #fff3e0;
            color: #e65100;
            border: 1px solid #e65100;
        }

        .severity-medium {
            background: #fffde7;
            color: #f9a825;
            border: 1px solid #f9a825;
        }

        .severity-low {
            background: #e8f5e9;
            color: #2e7d32;
            border: 1px solid #2e7d32;
        }

        .resource-name {
            font-family: 'Courier New', monospace;
            font-size: 9pt;
            color: #1565c0;
        }

        .recommendation {
            color: #666;
            font-size: 9pt;
            margin-top: 6px;
            font-style: italic;
        }

        .compliance-badges {
            margin-top: 6px;
        }

        .compliance-badge {
            display: inline-block;
            padding: 2px 6px;
            margin: 2px;
            border-radius: 3px;
            font-size: 8pt;
            background: #e3f2fd;
            color: #1565c0;
            border: 1px solid #90caf9;
        }

        .no-findings {
            text-align: center;
            padding: 30px;
            color: #666;
            background: #f9f9f9;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 9pt;
            border-top: 1px solid #ddd;
            margin-top: 30px;
        }

        .executive-summary {
            background: #f5f5f5;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 8px;
        }

        .executive-summary h2 {
            font-size: 14pt;
            color: #232f3e;
            margin-bottom: 15px;
        }

        .executive-summary p {
            margin-bottom: 10px;
        }

        .risk-level {
            font-weight: bold;
            padding: 5px 15px;
            border-radius: 4px;
            display: inline-block;
        }

        .risk-level.excellent { background: #e8f5e9; color: #2e7d32; }
        .risk-level.good { background: #e3f2fd; color: #1565c0; }
        .risk-level.needs-improvement { background: #fff3e0; color: #e65100; }
        .risk-level.critical { background: #ffebee; color: #c62828; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AWS Security Posture Report</h1>
        <p class="meta">Account: <strong>{{.AccountID}}</strong> | Generated: {{.GeneratedAt}}</p>
    </div>

    <div class="executive-summary">
        <h2>Executive Summary</h2>
        <p>Security Score: <span class="risk-level {{.Summary.ScoreDescription | lower}}">{{.Summary.SecurityScore}}/100 - {{.Summary.ScoreDescription}}</span></p>
        <p>Total Findings: {{.Summary.TotalFindings}} ({{.Summary.CriticalCount}} Critical, {{.Summary.HighCount}} High, {{.Summary.MediumCount}} Medium, {{.Summary.LowCount}} Low)</p>
    </div>

    <div class="summary-grid">
        <div class="summary-card score">
            <h3>Security Score</h3>
            <div class="value">{{.Summary.SecurityScore}}</div>
        </div>
        <div class="summary-card critical">
            <h3>Critical</h3>
            <div class="value">{{.Summary.CriticalCount}}</div>
        </div>
        <div class="summary-card high">
            <h3>High</h3>
            <div class="value">{{.Summary.HighCount}}</div>
        </div>
        <div class="summary-card medium">
            <h3>Medium</h3>
            <div class="value">{{.Summary.MediumCount}}</div>
        </div>
        <div class="summary-card low">
            <h3>Low</h3>
            <div class="value">{{.Summary.LowCount}}</div>
        </div>
    </div>

    {{range .Sections}}
    {{if .Findings}}
    <div class="section">
        <div class="section-header">
            <h2>{{.Title}} ({{len .Findings}} findings)</h2>
        </div>
        <table class="findings-table">
            <thead>
                <tr>
                    <th style="width: 90px;">Severity</th>
                    <th style="width: 180px;">Resource</th>
                    <th>Issue & Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {{range .Findings}}
                <tr>
                    <td>
                        <span class="severity-badge severity-{{.Severity | lower}}">{{.Severity}}</span>
                    </td>
                    <td class="resource-name">{{.Resource}}</td>
                    <td>
                        <strong>{{.Title}}</strong>
                        {{if .Description}}<br>{{.Description}}{{end}}
                        {{if .Recommendation}}
                        <div class="recommendation">💡 {{.Recommendation}}</div>
                        {{end}}
                        {{if .Compliance}}
                        <div class="compliance-badges">
                            {{range .Compliance}}<span class="compliance-badge">{{.}}</span>{{end}}
                        </div>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
    {{end}}
    {{end}}

    <div class="footer">
        <p>Generated by aws-perimeter | Confidential Security Report</p>
        <p>This report should be treated as sensitive security information.</p>
    </div>
</body>
</html>`
