# SQLite Historical Trending Dashboard - Design Document

## Executive Summary

**Question:** Can we use SQLite for historical trending dashboard?

**Answer:** ✅ **YES** - SQLite is an excellent choice for this use case.

---

## Why SQLite is Perfect for This

### ✅ Advantages

1. **Zero-Configuration**
   - No separate database server required
   - Single file database (`~/.aws-perimeter/history.db`)
   - Works out-of-the-box on all platforms

2. **Lightweight & Fast**
   - ~600KB library size
   - Serverless (embedded in Go binary)
   - Fast queries for time-series data

3. **Cross-Platform**
   - Works on macOS, Linux, Windows
   - Pure Go driver available (`modernc.org/sqlite` or `mattn/go-sqlite3`)
   - No external dependencies

4. **Perfect for CLI Tools**
   - Local storage (no cloud dependency)
   - User controls their data
   - Easy backup (copy single file)

5. **Rich Query Capabilities**
   - SQL for time-series queries
   - Aggregations, trends, comparisons
   - Full-text search for findings

6. **Mature Ecosystem**
   - Battle-tested (used by browsers, mobile apps)
   - Excellent documentation
   - Go libraries well-maintained

### ⚠️ Limitations (Not Issues for This Use Case)

1. **Concurrency** - Not an issue (single-user CLI tool)
2. **Scale** - Not an issue (findings data is small, ~1-10MB per scan)
3. **Network** - Not an issue (local-only tool)

---

## Proposed Architecture

```
┌────────────────────────────────────────────────────────┐
│                   aws-perimeter CLI                    │
└───────────────┬────────────────────────────────────────┘
                │
                ▼
┌────────────────────────────────────────────────────────┐
│              Storage Layer (New)                       │
│  ┌──────────────────────────────────────────────────┐ │
│  │   service/storage/sqlite.go                      │ │
│  │   - InitDB()                                     │ │
│  │   - SaveScanResults()                            │ │
│  │   - GetTrends()                                  │ │
│  │   - GetComparisonData()                          │ │
│  └──────────────────────────────────────────────────┘ │
└───────────────┬────────────────────────────────────────┘
                │
                ▼
┌────────────────────────────────────────────────────────┐
│  ~/.aws-perimeter/history.db (SQLite Database)        │
│                                                        │
│  Tables:                                               │
│  - scans                                               │
│  - findings                                            │
│  - metrics                                             │
│  - compliance_scores                                   │
└────────────────────────────────────────────────────────┘
```

---

## Database Schema Design

### Table: `scans`
Tracks each scan execution.

```sql
CREATE TABLE scans (
    scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_uuid       TEXT UNIQUE NOT NULL,           -- UUID for correlation
    account_id      TEXT NOT NULL,                  -- AWS Account ID
    region          TEXT NOT NULL,                  -- AWS Region
    scan_timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
    scan_duration   INTEGER,                        -- Duration in seconds
    total_findings  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    cli_version     TEXT,                           -- aws-perimeter version
    scan_profile    TEXT,                           -- AWS profile used
    scan_flags      TEXT,                           -- JSON of CLI flags
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_scans_account_timestamp 
    ON scans(account_id, scan_timestamp);
CREATE INDEX idx_scans_timestamp 
    ON scans(scan_timestamp DESC);
```

### Table: `findings`
Stores individual security findings.

```sql
CREATE TABLE findings (
    finding_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    finding_hash    TEXT NOT NULL,                  -- Hash for deduplication
    category        TEXT NOT NULL,                  -- VPC, IAM, S3, etc.
    subcategory     TEXT,                           -- SecurityGroup, PrivEsc, etc.
    risk_type       TEXT NOT NULL,                  -- OPEN_SSH, PUBLIC_S3, etc.
    severity        TEXT NOT NULL,                  -- CRITICAL, HIGH, MEDIUM, LOW
    resource_type   TEXT,                           -- Instance, User, Bucket, etc.
    resource_id     TEXT,                           -- i-1234, user-name, bucket-name
    resource_arn    TEXT,                           -- Full ARN if available
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    recommendation  TEXT,
    compliance_tags TEXT,                           -- JSON: CIS, PCI-DSS, etc.
    first_seen      DATETIME NOT NULL,              -- When first detected
    last_seen       DATETIME NOT NULL,              -- Most recent detection
    resolved_at     DATETIME,                       -- When no longer detected
    status          TEXT DEFAULT 'OPEN',            -- OPEN, RESOLVED, IGNORED
    
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_hash ON findings(finding_hash);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_resource ON findings(resource_id);
CREATE INDEX idx_findings_category ON findings(category);
```

### Table: `metrics`
Pre-calculated metrics for dashboard performance.

```sql
CREATE TABLE metrics (
    metric_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    metric_name     TEXT NOT NULL,                  -- total_findings, mttr, etc.
    metric_value    REAL NOT NULL,
    metric_unit     TEXT,                           -- count, days, percent
    category        TEXT,                           -- Overall, IAM, VPC, etc.
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_metrics_scan ON metrics(scan_id);
CREATE INDEX idx_metrics_name ON metrics(metric_name);
```

### Table: `compliance_scores`
Compliance framework scores over time.

```sql
CREATE TABLE compliance_scores (
    score_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    framework       TEXT NOT NULL,                  -- CIS, PCI-DSS, NIST
    version         TEXT,                           -- Framework version
    score           REAL NOT NULL,                  -- 0-100
    passed_checks   INTEGER DEFAULT 0,
    failed_checks   INTEGER DEFAULT 0,
    not_applicable  INTEGER DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_compliance_scan ON compliance_scores(scan_id);
CREATE INDEX idx_compliance_framework ON compliance_scores(framework);
```

---

## Implementation Approach

### Phase 1: Core Storage Layer

#### 1. Add SQLite Dependency

```go
// go.mod
require (
    modernc.org/sqlite v1.28.0  // Pure Go, no CGO
    // OR
    github.com/mattn/go-sqlite3 v1.14.18  // Faster, requires CGO
)
```

**Recommendation:** Use `modernc.org/sqlite` for easier cross-compilation.

#### 2. Create Storage Service

```go
// service/storage/sqlite.go
package storage

import (
    "database/sql"
    "fmt"
    "time"
    
    _ "modernc.org/sqlite"
)

type Service interface {
    SaveScan(scan *ScanResult) error
    GetRecentScans(accountID string, limit int) ([]ScanSummary, error)
    GetTrends(accountID string, days int) (*TrendData, error)
    GetFindingHistory(findingHash string) ([]FindingOccurrence, error)
    Close() error
}

type service struct {
    db *sql.DB
    dbPath string
}

func NewService(dbPath string) (Service, error) {
    db, err := sql.Open("sqlite", dbPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to connect: %w", err)
    }
    
    s := &service{db: db, dbPath: dbPath}
    
    if err := s.initSchema(); err != nil {
        return nil, err
    }
    
    return s, nil
}

func (s *service) initSchema() error {
    schema := `
    CREATE TABLE IF NOT EXISTS scans (
        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_uuid TEXT UNIQUE NOT NULL,
        account_id TEXT NOT NULL,
        region TEXT NOT NULL,
        scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        scan_duration INTEGER,
        total_findings INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        info_count INTEGER DEFAULT 0,
        cli_version TEXT,
        scan_profile TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_scans_account_timestamp 
        ON scans(account_id, scan_timestamp);
    
    CREATE TABLE IF NOT EXISTS findings (
        finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        finding_hash TEXT NOT NULL,
        category TEXT NOT NULL,
        risk_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        resource_type TEXT,
        resource_id TEXT,
        resource_arn TEXT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        recommendation TEXT,
        first_seen DATETIME NOT NULL,
        last_seen DATETIME NOT NULL,
        resolved_at DATETIME,
        status TEXT DEFAULT 'OPEN',
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_findings_hash 
        ON findings(finding_hash);
    CREATE INDEX IF NOT EXISTS idx_findings_status 
        ON findings(status);
    `
    
    _, err := s.db.Exec(schema)
    return err
}

func (s *service) SaveScan(scan *ScanResult) error {
    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    // Insert scan record
    result, err := tx.Exec(`
        INSERT INTO scans (
            scan_uuid, account_id, region, scan_timestamp,
            scan_duration, total_findings, critical_count,
            high_count, medium_count, low_count, info_count,
            cli_version, scan_profile
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, scan.UUID, scan.AccountID, scan.Region, scan.Timestamp,
       scan.Duration, scan.TotalFindings, scan.CriticalCount,
       scan.HighCount, scan.MediumCount, scan.LowCount,
       scan.InfoCount, scan.Version, scan.Profile)
    
    if err != nil {
        return err
    }
    
    scanID, err := result.LastInsertId()
    if err != nil {
        return err
    }
    
    // Insert findings
    for _, finding := range scan.Findings {
        hash := generateFindingHash(finding)
        
        // Check if finding already exists
        var existingID int64
        err := tx.QueryRow(`
            SELECT finding_id FROM findings
            WHERE finding_hash = ? AND status = 'OPEN'
        `, hash).Scan(&existingID)
        
        if err == sql.ErrNoRows {
            // New finding
            _, err = tx.Exec(`
                INSERT INTO findings (
                    scan_id, finding_hash, category, risk_type,
                    severity, resource_type, resource_id, resource_arn,
                    title, description, recommendation,
                    first_seen, last_seen, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')
            `, scanID, hash, finding.Category, finding.RiskType,
               finding.Severity, finding.ResourceType, finding.ResourceID,
               finding.ResourceARN, finding.Title, finding.Description,
               finding.Recommendation, scan.Timestamp, scan.Timestamp)
        } else {
            // Update existing finding
            _, err = tx.Exec(`
                UPDATE findings
                SET last_seen = ?, scan_id = ?
                WHERE finding_id = ?
            `, scan.Timestamp, scanID, existingID)
        }
        
        if err != nil {
            return err
        }
    }
    
    // Mark resolved findings
    _, err = tx.Exec(`
        UPDATE findings
        SET status = 'RESOLVED', resolved_at = ?
        WHERE status = 'OPEN'
        AND finding_hash NOT IN (
            SELECT finding_hash FROM findings WHERE scan_id = ?
        )
    `, scan.Timestamp, scanID)
    
    if err != nil {
        return err
    }
    
    return tx.Commit()
}

func (s *service) GetTrends(accountID string, days int) (*TrendData, error) {
    query := `
    SELECT 
        DATE(scan_timestamp) as scan_date,
        AVG(total_findings) as avg_findings,
        AVG(critical_count) as avg_critical,
        AVG(high_count) as avg_high,
        AVG(medium_count) as avg_medium
    FROM scans
    WHERE account_id = ?
    AND scan_timestamp >= datetime('now', '-' || ? || ' days')
    GROUP BY DATE(scan_timestamp)
    ORDER BY scan_date ASC
    `
    
    rows, err := s.db.Query(query, accountID, days)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    trends := &TrendData{
        AccountID: accountID,
        Days:      days,
        DataPoints: make([]TrendDataPoint, 0),
    }
    
    for rows.Next() {
        var dp TrendDataPoint
        err := rows.Scan(
            &dp.Date,
            &dp.AvgFindings,
            &dp.AvgCritical,
            &dp.AvgHigh,
            &dp.AvgMedium,
        )
        if err != nil {
            return nil, err
        }
        trends.DataPoints = append(trends.DataPoints, dp)
    }
    
    return trends, nil
}

func (s *service) Close() error {
    return s.db.Close()
}

// Helper function to generate consistent hash for findings
func generateFindingHash(f *Finding) string {
    // Hash based on: category + risk_type + resource_id
    data := fmt.Sprintf("%s:%s:%s", f.Category, f.RiskType, f.ResourceID)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
```

#### 3. Data Models

```go
// service/storage/types.go
package storage

import "time"

type ScanResult struct {
    UUID           string
    AccountID      string
    Region         string
    Timestamp      time.Time
    Duration       int
    TotalFindings  int
    CriticalCount  int
    HighCount      int
    MediumCount    int
    LowCount       int
    InfoCount      int
    Version        string
    Profile        string
    Findings       []*Finding
}

type Finding struct {
    Category       string
    RiskType       string
    Severity       string
    ResourceType   string
    ResourceID     string
    ResourceARN    string
    Title          string
    Description    string
    Recommendation string
}

type TrendData struct {
    AccountID  string
    Days       int
    DataPoints []TrendDataPoint
}

type TrendDataPoint struct {
    Date        string
    AvgFindings float64
    AvgCritical float64
    AvgHigh     float64
    AvgMedium   float64
}

type ScanSummary struct {
    ScanID        int64
    ScanUUID      string
    AccountID     string
    Region        string
    Timestamp     time.Time
    TotalFindings int
    CriticalCount int
    HighCount     int
}

type FindingOccurrence struct {
    ScanID      int64
    Timestamp   time.Time
    Status      string
    ResourceID  string
}
```

### Phase 2: CLI Integration

#### 1. Add Storage Flags

```go
// service/flag/service.go

type Flags struct {
    // ... existing flags ...
    
    // Storage flags
    EnableStorage  bool
    StoragePath    string
    ShowTrends     bool
    TrendDays      int
    CompareScans   bool
    CompareScanIDs string
}

func (s *service) GetParsedFlags() (model.Flags, error) {
    // ... existing code ...
    
    fs.BoolVar(&flags.EnableStorage, "store", false, "Store scan results in SQLite database")
    fs.StringVar(&flags.StoragePath, "db-path", "~/.aws-perimeter/history.db", "Path to SQLite database")
    fs.BoolVar(&flags.ShowTrends, "trends", false, "Show historical trends")
    fs.IntVar(&flags.TrendDays, "trend-days", 30, "Number of days for trend analysis")
    fs.BoolVar(&flags.CompareScans, "compare", false, "Compare current scan with previous")
    
    return flags, nil
}
```

#### 2. Integrate in Orchestrator

```go
// service/orchestrator/service.go

func (s *service) securityWorkflow(flags model.Flags) error {
    // ... existing scan logic ...
    
    // After scan completes
    if flags.EnableStorage {
        storageService, err := storage.NewService(flags.StoragePath)
        if err != nil {
            log.Printf("Warning: Could not initialize storage: %v", err)
        } else {
            defer storageService.Close()
            
            scanResult := buildScanResult(stsResult, allFindings, flags)
            if err := storageService.SaveScan(scanResult); err != nil {
                log.Printf("Warning: Could not save scan: %v", err)
            } else {
                fmt.Println("✅ Scan results stored in database")
            }
        }
    }
    
    // Show trends if requested
    if flags.ShowTrends {
        storageService, _ := storage.NewService(flags.StoragePath)
        defer storageService.Close()
        
        trends, _ := storageService.GetTrends(*stsResult.Account, flags.TrendDays)
        renderTrends(trends)
    }
    
    return nil
}
```

### Phase 3: Trending Dashboard

#### 1. CLI Trend Visualization

```go
// shared/trends/trends.go
package trends

import (
    "fmt"
    "github.com/jedib0t/go-pretty/v6/table"
)

func RenderTrendTable(trends *storage.TrendData) {
    t := table.NewWriter()
    t.SetTitle("📈 Security Posture Trends (" + fmt.Sprintf("%d days", trends.Days) + ")")
    
    t.AppendHeader(table.Row{
        "Date", "Total Findings", "Critical", "High", "Medium", "Trend"
    })
    
    for i, dp := range trends.DataPoints {
        trend := "→"
        if i > 0 {
            prev := trends.DataPoints[i-1]
            if dp.AvgFindings < prev.AvgFindings {
                trend = "↓ Improving"
            } else if dp.AvgFindings > prev.AvgFindings {
                trend = "↑ Degrading"
            }
        }
        
        t.AppendRow(table.Row{
            dp.Date,
            fmt.Sprintf("%.0f", dp.AvgFindings),
            fmt.Sprintf("%.0f", dp.AvgCritical),
            fmt.Sprintf("%.0f", dp.AvgHigh),
            fmt.Sprintf("%.0f", dp.AvgMedium),
            trend,
        })
    }
    
    fmt.Println(t.Render())
}

func RenderComparisonTable(current, previous *storage.ScanSummary) {
    t := table.NewWriter()
    t.SetTitle("🔄 Scan Comparison")
    
    t.AppendHeader(table.Row{"Metric", "Previous", "Current", "Change"})
    
    rows := []struct {
        name     string
        prev     int
        curr     int
    }{
        {"Total Findings", previous.TotalFindings, current.TotalFindings},
        {"Critical", previous.CriticalCount, current.CriticalCount},
        {"High", previous.HighCount, current.HighCount},
    }
    
    for _, row := range rows {
        delta := row.curr - row.prev
        change := fmt.Sprintf("%+d", delta)
        if delta < 0 {
            change = fmt.Sprintf("✅ %d", delta)
        } else if delta > 0 {
            change = fmt.Sprintf("⚠️ +%d", delta)
        } else {
            change = "—"
        }
        
        t.AppendRow(table.Row{
            row.name, row.prev, row.curr, change,
        })
    }
    
    fmt.Println(t.Render())
}
```

#### 2. ASCII Chart (Optional)

```go
// Simple sparkline for CLI
func renderSparkline(values []float64) string {
    chars := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
    // Normalize and convert to sparkline
    // ...
}
```

---

## Usage Examples

### 1. Basic Scan with Storage

```bash
# Enable storage (creates ~/.aws-perimeter/history.db)
aws-perimeter --store

# Custom database path
aws-perimeter --store --db-path /var/security/scans.db
```

### 2. View Trends

```bash
# Show 30-day trends
aws-perimeter --trends

# Show 90-day trends
aws-perimeter --trends --trend-days 90
```

### 3. Compare Scans

```bash
# Compare with previous scan
aws-perimeter --store --compare

# Output:
# 🔄 Scan Comparison
# ┌─────────────────┬──────────┬─────────┬─────────┐
# │ Metric          │ Previous │ Current │ Change  │
# ├─────────────────┼──────────┼─────────┼─────────┤
# │ Total Findings  │ 47       │ 42      │ ✅ -5   │
# │ Critical        │ 12       │ 8       │ ✅ -4   │
# │ High            │ 18       │ 15      │ ✅ -3   │
# └─────────────────┴──────────┴─────────┴─────────┘
```

### 4. Historical Queries

```bash
# Show all scans
aws-perimeter history list

# Show finding lifecycle
aws-perimeter history finding <finding-hash>

# Export trends to CSV
aws-perimeter trends --format csv > trends.csv
```

---

## Advanced Features

### 1. Mean Time To Remediate (MTTR)

```sql
SELECT 
    category,
    AVG(JULIANDAY(resolved_at) - JULIANDAY(first_seen)) as avg_days_to_resolve
FROM findings
WHERE status = 'RESOLVED'
GROUP BY category;
```

### 2. Top Persistent Findings

```sql
SELECT 
    risk_type,
    COUNT(*) as occurrences,
    MIN(first_seen) as first_seen,
    MAX(last_seen) as last_seen
FROM findings
WHERE status = 'OPEN'
GROUP BY risk_type
ORDER BY occurrences DESC
LIMIT 10;
```

### 3. Security Posture Score

```sql
-- Calculate score: 100 - (weighted severity points)
SELECT 
    scan_id,
    100 - (
        (critical_count * 10) +
        (high_count * 5) +
        (medium_count * 2) +
        (low_count * 1)
    ) as security_score
FROM scans
ORDER BY scan_timestamp DESC
LIMIT 30;
```

---

## Alternative: Web Dashboard

If you want a web UI, keep SQLite and add:

```go
// cmd/dashboard/main.go
package main

import (
    "net/http"
    "html/template"
)

func main() {
    storage := storage.NewService("~/.aws-perimeter/history.db")
    
    http.HandleFunc("/", dashboardHandler)
    http.HandleFunc("/api/trends", trendsAPIHandler)
    http.HandleFunc("/api/scans", scansAPIHandler)
    
    log.Println("Dashboard running on http://localhost:8080")
    http.ListenAndServe(":8080", nil)
}
```

Use lightweight UI: **htmx** + **Chart.js** for interactive charts.

---

## Migration Path

### Phase 1: Foundation (Week 1-2)
- [ ] Add SQLite dependency
- [ ] Create storage service
- [ ] Implement schema migrations
- [ ] Add `--store` flag

### Phase 2: Basic Trending (Week 3-4)
- [ ] Implement trend queries
- [ ] CLI trend visualization
- [ ] Scan comparison
- [ ] MTTR calculations

### Phase 3: Advanced Analytics (Week 5-6)
- [ ] Compliance scoring over time
- [ ] Finding lifecycle tracking
- [ ] Export to CSV/JSON
- [ ] Database maintenance commands

### Phase 4: Dashboard (Optional)
- [ ] Simple web UI
- [ ] Interactive charts
- [ ] Finding drill-down
- [ ] Multi-account views

---

## Performance Considerations

### Database Size Estimates

| Frequency | Duration | Findings/Scan | DB Size |
|-----------|----------|---------------|---------|
| Daily | 30 days | 50 | ~500 KB |
| Daily | 90 days | 50 | ~1.5 MB |
| Daily | 365 days | 50 | ~6 MB |
| Daily | 365 days | 200 | ~24 MB |

**Conclusion:** Even with daily scans for a year, database stays under 30MB.

### Query Performance

SQLite handles 100K+ rows efficiently with proper indexes:
- Finding lookups: <1ms
- Trend queries (30 days): <10ms
- Full scan history: <50ms

### Maintenance

```sql
-- Vacuum database monthly
VACUUM;

-- Rebuild indexes
REINDEX;

-- Purge old data (keep 1 year)
DELETE FROM scans WHERE scan_timestamp < datetime('now', '-365 days');
```

---

## Security Considerations

1. **Database Location**
   - Default: `~/.aws-perimeter/history.db` (user-only)
   - Permissions: `0600` (owner read/write only)

2. **Sensitive Data**
   - Don't store: IAM credentials, secrets, API keys
   - Do store: Resource IDs, ARNs, finding descriptions

3. **Backup**
   ```bash
   # Simple backup
   cp ~/.aws-perimeter/history.db ~/.aws-perimeter/history.db.backup
   
   # Automated daily backup
   0 0 * * * cp ~/.aws-perimeter/history.db ~/.aws-perimeter/backups/history-$(date +\%Y\%m\%d).db
   ```

---

## Conclusion

### ✅ Recommendation: **Use SQLite**

**Rationale:**
1. **Perfect fit** for CLI tool with local storage needs
2. **Zero infrastructure** - no database server required
3. **Rich analytics** - SQL enables complex trend queries
4. **User control** - data stays local, easy backup
5. **Proven technology** - SQLite powers millions of applications

**Next Steps:**
1. Start with Phase 1 (storage foundation)
2. Implement basic trend queries
3. Add CLI visualization
4. Consider web dashboard later if needed

**Estimated Effort:** 2-3 weeks for full implementation

---

**Alternative Options (Not Recommended):**

| Option | Pros | Cons |
|--------|------|------|
| JSON Files | Simple | Hard to query, no relationships |
| PostgreSQL/MySQL | Powerful | Requires server, overkill |
| CSV | Easy export | No relationships, poor query |
| Cloud DB | Scalable | Requires internet, cost |

**Winner:** SQLite ✅
