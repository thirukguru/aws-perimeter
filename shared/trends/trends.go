package trends

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/thirukguru/aws-perimeter/service/storage"
)

// RenderTrendTable prints an ASCII table of trend data.
func RenderTrendTable(points []storage.TrendPoint) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Account", "Region", "Date", "Total", "Critical", "High", "Medium", "Low", "Score"})
	for _, p := range points {
		t.AppendRow(table.Row{p.AccountID, p.Region, p.Date, p.Total, p.Critical, p.High, p.Medium, p.Low, p.Score})
	}
	t.SetStyle(table.StyleRounded)
	t.Render()
}

// RenderComparisonTable prints comparison summary for two scans.
func RenderComparisonTable(cmp *storage.ScanComparison) {
	if cmp == nil {
		fmt.Println("No comparison data available")
		return
	}
	fmt.Printf("\nScan Comparison (%d -> %d)\n", cmp.ScanID1, cmp.ScanID2)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"New", "Resolved", "Persistent"})
	t.AppendRow(table.Row{cmp.NewFindings, cmp.Resolved, cmp.Persistent})
	t.SetStyle(table.StyleRounded)
	t.Render()
}
