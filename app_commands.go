package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"github.com/thirukguru/aws-perimeter/service/storage"
	"github.com/thirukguru/aws-perimeter/shared/trends"
)

func runStorageCommand(cmd string, args []string) error {
	switch cmd {
	case "db":
		return runDBCommand(args)
	case "history":
		return runHistoryCommand(args)
	case "dashboard":
		return runDashboardCommand(args)
	default:
		return fmt.Errorf("unsupported command: %s", cmd)
	}
}

func runDBCommand(args []string) error {
	fs := pflag.NewFlagSet("db", pflag.ContinueOnError)
	dbPath := fs.String("db-path", "", "SQLite database path")
	olderThan := fs.Int("older-than", 30, "Purge scans older than N days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: aws-perimeter db <vacuum|reindex|purge> [--db-path ...]")
	}

	store, err := storage.NewService(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	sub := rest[0]
	switch sub {
	case "vacuum":
		return store.Vacuum(context.Background())
	case "reindex":
		return store.Reindex(context.Background())
	case "purge":
		count, err := store.PurgeOlderThan(context.Background(), *olderThan)
		if err != nil {
			return err
		}
		fmt.Printf("Purged %d scans\n", count)
		return nil
	default:
		return fmt.Errorf("unsupported db command: %s", sub)
	}
}

func runHistoryCommand(args []string) error {
	fs := pflag.NewFlagSet("history", pflag.ContinueOnError)
	dbPath := fs.String("db-path", "", "SQLite database path")
	accountID := fs.String("account-id", "", "AWS account ID filter")
	limit := fs.Int("limit", 20, "Number of rows to list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: aws-perimeter history <list|show|finding>")
	}

	store, err := storage.NewService(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	sub := rest[0]
	switch sub {
	case "list":
		scans, err := store.GetRecentScans(*accountID, *limit)
		if err != nil {
			return err
		}
		for _, s := range scans {
			fmt.Printf("%d\t%s\t%s\t%s\t%d\n", s.ScanID, s.ScanTimestamp.Format("2006-01-02 15:04:05"), s.AccountID, s.Region, s.TotalFindings)
		}
		return nil
	case "show":
		if len(rest) < 2 {
			return fmt.Errorf("usage: aws-perimeter history show <scan-id>")
		}
		scanID, err := strconv.ParseInt(rest[1], 10, 64)
		if err != nil {
			return err
		}
		findings, err := store.ListFindings(scanID)
		if err != nil {
			return err
		}
		for _, f := range findings {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Category, f.RiskType, f.ResourceID, f.Title)
		}
		return nil
	case "finding":
		if len(rest) < 2 {
			return fmt.Errorf("usage: aws-perimeter history finding <hash>")
		}
		events, err := store.GetFindingLifecycle(rest[1])
		if err != nil {
			return err
		}
		for _, e := range events {
			fmt.Printf("scan=%d\t%s\t%s\t%s\t%s\n", e.ScanID, e.ScanTimestamp.Format("2006-01-02 15:04:05"), e.Status, e.Severity, e.ResourceID)
		}
		return nil
	default:
		return fmt.Errorf("unsupported history command: %s", sub)
	}
}

func runDashboardCommand(args []string) error {
	fs := pflag.NewFlagSet("dashboard", pflag.ContinueOnError)
	dbPath := fs.String("db-path", "", "SQLite database path")
	port := fs.Int("port", 8080, "Dashboard HTTP port")
	accountID := fs.String("account-id", "", "AWS account ID filter")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := storage.NewService(*dbPath)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>aws-perimeter dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: sans-serif; margin: 24px; color: #1f2937; }
    h1 { margin: 0 0 12px; }
    .meta { margin-bottom: 16px; color: #6b7280; }
    .panel { border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid #e5e7eb; padding: 8px; text-align: left; }
    th { background: #f9fafb; }
    .error { color: #b91c1c; white-space: pre-wrap; }
  </style>
</head>
<body>
  <h1>AWS Perimeter Dashboard</h1>
  <div class="meta">Source: <code>/api/trends</code></div>
  <div class="panel">
    <canvas id="trend" height="80"></canvas>
    <div id="chart-status"></div>
  </div>
  <div class="panel">
    <h3>Trend Data</h3>
    <div id="table-wrap">Loading...</div>
  </div>
  <script>
    const tableWrap = document.getElementById('table-wrap');
    const chartStatus = document.getElementById('chart-status');

    function renderTable(rows) {
      if (!rows || rows.length === 0) {
        tableWrap.innerHTML = '<em>No trend data found.</em>';
        return;
      }
      let html = '<table><thead><tr><th>Region</th><th>Date</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Score</th></tr></thead><tbody>';
      for (const r of rows) {
        html += '<tr>' +
          '<td>' + (r.region || '-') + '</td>' +
          '<td>' + r.date + '</td>' +
          '<td>' + r.total + '</td>' +
          '<td>' + r.critical + '</td>' +
          '<td>' + r.high + '</td>' +
          '<td>' + r.medium + '</td>' +
          '<td>' + r.low + '</td>' +
          '<td>' + r.score + '</td>' +
          '</tr>';
      }
      html += '</tbody></table>';
      tableWrap.innerHTML = html;
    }

    fetch('/api/trends')
      .then(r => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(rows => {
        renderTable(rows);
        if (!rows || rows.length === 0) return;
        if (typeof Chart !== 'function') {
          chartStatus.innerHTML = '<div class="error">Chart.js failed to load; showing table fallback.</div>';
          return;
        }
        const labels = rows.map(x => (x.region ? (x.region + ' ') : '') + x.date);
        const vals = rows.map(x => x.total);
        new Chart(document.getElementById('trend'), {
          type: 'line',
          data: { labels: labels, datasets: [{ label: 'Findings', data: vals, borderColor: '#ff9900' }] },
          options: {
            responsive: true,
            plugins: {
              legend: { display: true }
            },
            scales: {
              x: {
                title: {
                  display: true,
                  text: 'Region + Date'
                }
              },
              y: {
                title: {
                  display: true,
                  text: 'Total Findings'
                },
                beginAtZero: true
              }
            }
          }
        });
      })
      .catch(err => {
        tableWrap.innerHTML = '<div class="error">Failed to load trend data: ' + err.message + '</div>';
        chartStatus.innerHTML = '<div class="error">Chart not rendered.</div>';
      });
  </script>
</body>
</html>`))
	})
	mux.HandleFunc("/api/trends", func(w http.ResponseWriter, _ *http.Request) {
		points, err := store.GetTrends(*accountID, 30)
		writeJSON(w, points, err)
	})
	mux.HandleFunc("/api/scans", func(w http.ResponseWriter, _ *http.Request) {
		scans, err := store.GetRecentScans(*accountID, 50)
		writeJSON(w, scans, err)
	})
	mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		scanIDStr := r.URL.Query().Get("scan_id")
		if scanIDStr == "" {
			http.Error(w, "scan_id is required", http.StatusBadRequest)
			return
		}
		scanID, err := strconv.ParseInt(scanIDStr, 10, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		findings, err := store.ListFindings(scanID)
		writeJSON(w, findings, err)
	})

	addr := fmt.Sprintf(":%d", *port)
	fmt.Printf("Dashboard running on http://localhost%s\n", addr)
	err = http.ListenAndServe(addr, mux)
	_ = store.Close()
	return err
}

func runTrendWorkflow(store storage.Service, flags struct {
	TrendDays  int
	Compare    bool
	ExportJSON string
	ExportCSV  string
	AccountID  string
}) error {
	points, err := store.GetTrends(flags.AccountID, flags.TrendDays)
	if err != nil {
		return err
	}
	trends.RenderTrendTable(points)

	if flags.Compare {
		scans, err := store.GetRecentScans(flags.AccountID, 2)
		if err == nil && len(scans) >= 2 {
			cmp, err := store.GetScanComparison(scans[1].ScanID, scans[0].ScanID)
			if err == nil {
				trends.RenderComparisonTable(cmp)
			}
		}
	}

	if strings.TrimSpace(flags.ExportJSON) != "" {
		b, err := json.MarshalIndent(points, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(flags.ExportJSON, b, 0o644); err != nil {
			return err
		}
	}
	if strings.TrimSpace(flags.ExportCSV) != "" {
		f, err := os.Create(flags.ExportCSV)
		if err != nil {
			return err
		}
		defer f.Close()
		w := csv.NewWriter(f)
		defer w.Flush()
		_ = w.Write([]string{"region", "date", "total", "critical", "high", "medium", "low", "info", "score"})
		for _, p := range points {
			_ = w.Write([]string{p.Region, p.Date, strconv.Itoa(p.Total), strconv.Itoa(p.Critical), strconv.Itoa(p.High), strconv.Itoa(p.Medium), strconv.Itoa(p.Low), strconv.Itoa(p.Info), strconv.Itoa(p.Score)})
		}
	}

	return nil
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
