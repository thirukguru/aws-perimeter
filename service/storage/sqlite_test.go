package storage

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
)

func newTestStorage(t *testing.T) Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "history.db")
	svc, err := NewService(dbPath)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func TestSaveScanAndQueries(t *testing.T) {
	svc := newTestStorage(t)
	ctx := context.Background()

	scanID, err := svc.SaveScan(ctx, SaveScanInput{
		ScanUUID:      "scan-1",
		AccountID:     "111111111111",
		Region:        "us-east-1",
		CriticalCount: 1,
		HighCount:     0,
		MediumCount:   1,
		LowCount:      0,
		InfoCount:     0,
		Findings: []Finding{
			{Hash: "h-a", Category: "IAM", RiskType: "PrivEsc", Severity: "CRITICAL", ResourceID: "user/alice", Title: "A", Description: "d"},
			{Hash: "h-b", Category: "S3", RiskType: "PublicBucket", Severity: "MEDIUM", ResourceID: "bucket-x", Title: "B", Description: "d"},
		},
	})
	if err != nil {
		t.Fatalf("SaveScan failed: %v", err)
	}
	if scanID <= 0 {
		t.Fatalf("expected positive scanID, got %d", scanID)
	}

	recent, err := svc.GetRecentScans("111111111111", 10)
	if err != nil {
		t.Fatalf("GetRecentScans failed: %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("expected 1 recent scan, got %d", len(recent))
	}
	if recent[0].Region != "us-east-1" || recent[0].TotalFindings != 2 {
		t.Fatalf("unexpected recent scan values: %+v", recent[0])
	}

	points, err := svc.GetTrends("111111111111", 30)
	if err != nil {
		t.Fatalf("GetTrends failed: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected 1 trend point, got %d", len(points))
	}
	if points[0].Region != "us-east-1" || points[0].Total != 2 || points[0].Score != 82 {
		t.Fatalf("unexpected trend point: %+v", points[0])
	}

	findings, err := svc.ListFindings(scanID)
	if err != nil {
		t.Fatalf("ListFindings failed: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestComparisonAndLifecycle(t *testing.T) {
	svc := newTestStorage(t)
	ctx := context.Background()

	scan1, err := svc.SaveScan(ctx, SaveScanInput{
		ScanUUID:      "scan-1",
		AccountID:     "222222222222",
		Region:        "us-west-2",
		CriticalCount: 1,
		MediumCount:   1,
		Findings: []Finding{
			{Hash: "h-a", Category: "IAM", RiskType: "PrivEsc", Severity: "CRITICAL", ResourceID: "u1", Title: "A", Description: "d"},
			{Hash: "h-b", Category: "S3", RiskType: "PublicBucket", Severity: "MEDIUM", ResourceID: "b1", Title: "B", Description: "d"},
		},
	})
	if err != nil {
		t.Fatalf("SaveScan #1 failed: %v", err)
	}

	scan2, err := svc.SaveScan(ctx, SaveScanInput{
		ScanUUID:      "scan-2",
		AccountID:     "222222222222",
		Region:        "us-west-2",
		CriticalCount: 1,
		Findings: []Finding{
			{Hash: "h-a", Category: "IAM", RiskType: "PrivEsc", Severity: "CRITICAL", ResourceID: "u1", Title: "A", Description: "d"},
		},
	})
	if err != nil {
		t.Fatalf("SaveScan #2 failed: %v", err)
	}

	cmp, err := svc.GetScanComparison(scan1, scan2)
	if err != nil {
		t.Fatalf("GetScanComparison failed: %v", err)
	}
	if cmp.NewFindings != 0 || cmp.Resolved != 1 || cmp.Persistent != 1 {
		t.Fatalf("unexpected comparison: %+v", cmp)
	}

	lifecycle, err := svc.GetFindingLifecycle("h-b")
	if err != nil {
		t.Fatalf("GetFindingLifecycle failed: %v", err)
	}
	if len(lifecycle) < 2 {
		t.Fatalf("expected at least 2 lifecycle events, got %d", len(lifecycle))
	}
	statuses := []string{lifecycle[0].Status, lifecycle[len(lifecycle)-1].Status}
	if statuses[0] != "OPEN" || statuses[1] != "RESOLVED" {
		t.Fatalf("unexpected lifecycle statuses: %v", statuses)
	}
}

func TestTrendsIncludeRegionDimension(t *testing.T) {
	svc := newTestStorage(t)
	ctx := context.Background()

	_, err := svc.SaveScan(ctx, SaveScanInput{
		ScanUUID:      "scan-east",
		AccountID:     "333333333333",
		Region:        "us-east-1",
		CriticalCount: 1,
		Findings:      []Finding{{Hash: "h-east", Category: "IAM", RiskType: "x", Severity: "CRITICAL", ResourceID: "r", Title: "t", Description: "d"}},
	})
	if err != nil {
		t.Fatalf("SaveScan east failed: %v", err)
	}
	_, err = svc.SaveScan(ctx, SaveScanInput{
		ScanUUID:  "scan-west",
		AccountID: "333333333333",
		Region:    "us-west-2",
		HighCount: 1,
		Findings:  []Finding{{Hash: "h-west", Category: "S3", RiskType: "x", Severity: "HIGH", ResourceID: "r", Title: "t", Description: "d"}},
	})
	if err != nil {
		t.Fatalf("SaveScan west failed: %v", err)
	}

	points, err := svc.GetTrends("333333333333", 30)
	if err != nil {
		t.Fatalf("GetTrends failed: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("expected 2 trend points, got %d", len(points))
	}
	regions := []string{points[0].Region, points[1].Region}
	sort.Strings(regions)
	if regions[0] != "us-east-1" || regions[1] != "us-west-2" {
		t.Fatalf("unexpected regions: %v", regions)
	}
}

func TestTrendsIncludeAccountDimensionAndFilter(t *testing.T) {
	svc := newTestStorage(t)
	ctx := context.Background()

	_, err := svc.SaveScan(ctx, SaveScanInput{
		ScanUUID:      "scan-a1",
		AccountID:     "444444444444",
		Region:        "us-east-1",
		CriticalCount: 1,
		Findings:      []Finding{{Hash: "h-a1", Category: "IAM", RiskType: "x", Severity: "CRITICAL", ResourceID: "r", Title: "t", Description: "d"}},
	})
	if err != nil {
		t.Fatalf("SaveScan account A failed: %v", err)
	}
	_, err = svc.SaveScan(ctx, SaveScanInput{
		ScanUUID:  "scan-b1",
		AccountID: "555555555555",
		Region:    "us-east-1",
		HighCount: 1,
		Findings:  []Finding{{Hash: "h-b1", Category: "S3", RiskType: "x", Severity: "HIGH", ResourceID: "r", Title: "t", Description: "d"}},
	})
	if err != nil {
		t.Fatalf("SaveScan account B failed: %v", err)
	}

	allPoints, err := svc.GetTrends("", 30)
	if err != nil {
		t.Fatalf("GetTrends (all accounts) failed: %v", err)
	}
	if len(allPoints) != 2 {
		t.Fatalf("expected 2 trend points across accounts, got %d", len(allPoints))
	}

	filtered, err := svc.GetTrends("444444444444", 30)
	if err != nil {
		t.Fatalf("GetTrends (filtered) failed: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered trend point, got %d", len(filtered))
	}
	if filtered[0].AccountID != "444444444444" {
		t.Fatalf("unexpected filtered account ID: %+v", filtered[0])
	}
}

func TestMaintenanceCommands(t *testing.T) {
	svc := newTestStorage(t)
	ctx := context.Background()

	if err := svc.Vacuum(ctx); err != nil {
		t.Fatalf("Vacuum failed: %v", err)
	}
	if err := svc.Reindex(ctx); err != nil {
		t.Fatalf("Reindex failed: %v", err)
	}
	if _, err := svc.PurgeOlderThan(ctx, 0); err == nil {
		t.Fatalf("expected error for invalid purge days")
	}
}
