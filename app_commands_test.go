package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thirukguru/aws-perimeter/service/storage"
)

type mockStorage struct {
	points []storage.TrendPoint
	scans  []storage.ScanSummary
	cmp    *storage.ScanComparison
}

func (m *mockStorage) SaveScan(context.Context, storage.SaveScanInput) (int64, error) {
	return 0, nil
}
func (m *mockStorage) GetTrends(accountID string, days int) ([]storage.TrendPoint, error) {
	return m.points, nil
}
func (m *mockStorage) GetRecentScans(accountID string, limit int) ([]storage.ScanSummary, error) {
	return m.scans, nil
}
func (m *mockStorage) GetScanComparison(scanID1, scanID2 int64) (*storage.ScanComparison, error) {
	return m.cmp, nil
}
func (m *mockStorage) GetFindingLifecycle(string) ([]storage.FindingLifecycleEvent, error) {
	return nil, nil
}
func (m *mockStorage) ListFindings(int64) ([]storage.FindingSnapshot, error) {
	return nil, nil
}
func (m *mockStorage) Vacuum(context.Context) error  { return nil }
func (m *mockStorage) Reindex(context.Context) error { return nil }
func (m *mockStorage) PurgeOlderThan(context.Context, int) (int64, error) {
	return 0, nil
}
func (m *mockStorage) Close() error { return nil }

func TestRunTrendWorkflowExports(t *testing.T) {
	tmp := t.TempDir()
	jsonPath := filepath.Join(tmp, "trends.json")
	csvPath := filepath.Join(tmp, "trends.csv")

	store := &mockStorage{
		points: []storage.TrendPoint{
			{Region: "us-east-1", Date: "2026-02-10", Total: 5, Critical: 1, High: 2, Medium: 1, Low: 1, Score: 60},
			{Region: "us-west-2", Date: "2026-02-10", Total: 2, Critical: 0, High: 1, Medium: 1, Low: 0, Score: 89},
		},
		scans: []storage.ScanSummary{{ScanID: 2, ScanTimestamp: time.Now()}, {ScanID: 1, ScanTimestamp: time.Now().Add(-time.Hour)}},
		cmp:   &storage.ScanComparison{ScanID1: 1, ScanID2: 2, NewFindings: 1, Resolved: 2, Persistent: 3},
	}

	err := runTrendWorkflow(store, struct {
		TrendDays  int
		Compare    bool
		ExportJSON string
		ExportCSV  string
		AccountID  string
	}{
		TrendDays:  30,
		Compare:    true,
		ExportJSON: jsonPath,
		ExportCSV:  csvPath,
		AccountID:  "111111111111",
	})
	if err != nil {
		t.Fatalf("runTrendWorkflow failed: %v", err)
	}

	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed reading exported json: %v", err)
	}
	var out []storage.TrendPoint
	if err := json.Unmarshal(jsonBytes, &out); err != nil {
		t.Fatalf("invalid json export: %v", err)
	}
	if len(out) != 2 || out[0].Region == "" {
		t.Fatalf("unexpected json export content: %+v", out)
	}

	csvBytes, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("failed reading exported csv: %v", err)
	}
	csv := string(csvBytes)
	if !strings.Contains(csv, "region,date,total") {
		t.Fatalf("csv header missing region/date/total: %s", csv)
	}
	if !strings.Contains(csv, "us-east-1") || !strings.Contains(csv, "us-west-2") {
		t.Fatalf("csv content missing expected regions: %s", csv)
	}
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, map[string]string{"status": "ok"}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("unexpected content type: %s", ct)
	}

	rr = httptest.NewRecorder()
	writeJSON(rr, nil, context.DeadlineExceeded)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for error path, got %d", rr.Code)
	}
}
