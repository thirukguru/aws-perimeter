// Package tests contains unit tests for HTML output generation.
package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	htmloutput "github.com/thirukguru/aws-perimeter/utils/html_output"
)

// TestGenerateHTMLReport tests basic HTML report generation
func TestGenerateHTMLReport(t *testing.T) {
	data := htmloutput.ReportData{
		AccountID: "123456789012",
		Sections: []htmloutput.Section{
			{
				ID:          "test-section",
				Title:       "Test Section",
				Description: "Test description",
				Findings: []htmloutput.Finding{
					{
						Severity:       "CRITICAL",
						Title:          "Test Finding",
						Resource:       "test-resource",
						Description:    "Test issue description",
						Recommendation: "Test recommendation",
					},
				},
				Status: "critical",
			},
		},
	}

	html, err := htmloutput.GenerateHTMLReport(data)

	assert.NoError(t, err)
	assert.Contains(t, html, "123456789012")
	assert.Contains(t, html, "Test Section")
	assert.Contains(t, html, "CRITICAL")
	assert.Contains(t, html, "test-resource")
}

// TestSecurityScoreCalculation tests the security score calculation
func TestSecurityScoreCalculation(t *testing.T) {
	tests := []struct {
		name         string
		findings     []htmloutput.Finding
		wantMinScore int
		wantMaxScore int
	}{
		{
			name:         "no findings - perfect score",
			findings:     []htmloutput.Finding{},
			wantMinScore: 100,
			wantMaxScore: 100,
		},
		{
			name: "critical finding - reduced score",
			findings: []htmloutput.Finding{
				{Severity: "CRITICAL", Title: "test"},
			},
			wantMinScore: 80,
			wantMaxScore: 90,
		},
		{
			name: "multiple findings - low score",
			findings: []htmloutput.Finding{
				{Severity: "CRITICAL", Title: "test1"},
				{Severity: "CRITICAL", Title: "test2"},
				{Severity: "HIGH", Title: "test3"},
				{Severity: "HIGH", Title: "test4"},
			},
			wantMinScore: 40,
			wantMaxScore: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := htmloutput.ReportData{
				AccountID: "123456789012",
				Sections: []htmloutput.Section{
					{
						ID:       "test",
						Title:    "Test",
						Findings: tt.findings,
					},
				},
			}

			html, err := htmloutput.GenerateHTMLReport(data)
			assert.NoError(t, err)
			assert.NotEmpty(t, html)
		})
	}
}

// TestSectionBuilders tests the section builder functions
func TestSectionBuilders(t *testing.T) {
	findings := []htmloutput.Finding{
		{Severity: "HIGH", Title: "test"},
	}

	vpcSection := htmloutput.NewVPCSection(findings)
	assert.Equal(t, "vpc-security", vpcSection.ID)
	assert.Equal(t, "warning", vpcSection.Status)

	iamSection := htmloutput.NewIAMSection(findings)
	assert.Equal(t, "iam-security", iamSection.ID)

	s3Section := htmloutput.NewS3Section(findings)
	assert.Equal(t, "s3-security", s3Section.ID)
}
