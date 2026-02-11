package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const defaultDBPath = "~/.aws-perimeter/history.db"

// NewService creates a SQLite-backed storage service.
func NewService(dbPath string) (Service, error) {
	resolved, err := resolvePath(dbPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", resolved)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	if _, err := db.Exec(schemaV1); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	return &service{db: db, dbPath: resolved}, nil
}

type service struct {
	db     *sql.DB
	dbPath string
}

func resolvePath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		p = defaultDBPath
	}
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to resolve home dir: %w", err)
		}
		if p == "~" {
			p = home
		} else {
			p = filepath.Join(home, p[2:])
		}
	}
	return filepath.Clean(p), nil
}

func (s *service) SaveScan(ctx context.Context, input SaveScanInput) (int64, error) {
	if input.AccountID == "" {
		return 0, errors.New("account id is required")
	}
	if input.Region == "" {
		input.Region = "unknown"
	}
	if input.ScanUUID == "" {
		input.ScanUUID = fmt.Sprintf("scan-%d", time.Now().UnixNano())
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO scans (
			scan_uuid, account_id, region, scan_duration, total_findings,
			critical_count, high_count, medium_count, low_count, info_count,
			cli_version, scan_profile, scan_flags
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, input.ScanUUID, input.AccountID, input.Region, input.DurationSec, len(input.Findings),
		input.CriticalCount, input.HighCount, input.MediumCount, input.LowCount, input.InfoCount,
		input.Version, input.Profile, input.FlagsJSON)
	if err != nil {
		return 0, err
	}
	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	if err = s.saveFindingsTx(ctx, tx, scanID, input); err != nil {
		return 0, err
	}
	if err = s.saveScanMetricsTx(ctx, tx, scanID, input); err != nil {
		return 0, err
	}

	err = tx.Commit()
	if err != nil {
		return 0, err
	}
	return scanID, nil
}

func (s *service) saveFindingsTx(ctx context.Context, tx *sql.Tx, scanID int64, input SaveScanInput) error {
	seen := make([]string, 0, len(input.Findings))
	now := time.Now().UTC().Format(time.RFC3339)

	for _, f := range input.Findings {
		if f.Hash == "" {
			continue
		}
		seen = append(seen, f.Hash)
		_, err := tx.ExecContext(ctx, `
			INSERT INTO findings (
				account_id, region, finding_hash, category, subcategory, risk_type, severity,
				resource_type, resource_id, resource_arn, title, description, recommendation,
				compliance_tags, first_seen, last_seen, status
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')
			ON CONFLICT(account_id, finding_hash) DO UPDATE SET
				region=excluded.region,
				category=excluded.category,
				subcategory=excluded.subcategory,
				risk_type=excluded.risk_type,
				severity=excluded.severity,
				resource_type=excluded.resource_type,
				resource_id=excluded.resource_id,
				resource_arn=excluded.resource_arn,
				title=excluded.title,
				description=excluded.description,
				recommendation=excluded.recommendation,
				compliance_tags=excluded.compliance_tags,
				last_seen=excluded.last_seen,
				resolved_at=NULL,
				status='OPEN'
		`, input.AccountID, input.Region, f.Hash, f.Category, f.Subcategory, f.RiskType, f.Severity,
			f.ResourceType, f.ResourceID, f.ResourceARN, f.Title, f.Description, f.Recommendation,
			f.ComplianceTags, now, now)
		if err != nil {
			return err
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO scan_findings(scan_id, finding_hash, severity, status, category, risk_type, resource_id, title)
			VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?)
		`, scanID, f.Hash, f.Severity, f.Category, f.RiskType, f.ResourceID, f.Title)
		if err != nil {
			return err
		}
	}

	if len(seen) == 0 {
		_, err := tx.ExecContext(ctx, `
			UPDATE findings SET status='RESOLVED', resolved_at=?, last_seen=?
			WHERE account_id=? AND status='OPEN'
		`, now, now, input.AccountID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO scan_findings(scan_id, finding_hash, severity, status, category, risk_type, resource_id, title)
			SELECT ?, finding_hash, severity, status, category, risk_type, resource_id, title
			FROM findings WHERE account_id=? AND status='RESOLVED' AND resolved_at=?
		`, scanID, input.AccountID, now)
		return err
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(seen)), ",")
	args := make([]any, 0, len(seen)+3)
	args = append(args, now, now, input.AccountID)
	for _, h := range seen {
		args = append(args, h)
	}

	query := fmt.Sprintf(`
		UPDATE findings SET status='RESOLVED', resolved_at=?, last_seen=?
		WHERE account_id=? AND status='OPEN' AND finding_hash NOT IN (%s)
	`, placeholders)
	_, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO scan_findings(scan_id, finding_hash, severity, status, category, risk_type, resource_id, title)
		SELECT ?, finding_hash, severity, status, category, risk_type, resource_id, title
		FROM findings WHERE account_id=? AND status='RESOLVED' AND resolved_at=?
	`, scanID, input.AccountID, now)
	if err != nil {
		return err
	}

	return nil
}

func (s *service) saveScanMetricsTx(ctx context.Context, tx *sql.Tx, scanID int64, input SaveScanInput) error {
	total := input.CriticalCount + input.HighCount + input.MediumCount + input.LowCount + input.InfoCount
	score := 100 - input.CriticalCount*15 - input.HighCount*8 - input.MediumCount*3 - input.LowCount
	if score < 0 {
		score = 0
	}
	metrics := []struct {
		name string
		val  float64
		unit string
	}{
		{"total_findings", float64(total), "count"},
		{"security_score", float64(score), "score"},
		{"critical_count", float64(input.CriticalCount), "count"},
		{"high_count", float64(input.HighCount), "count"},
		{"medium_count", float64(input.MediumCount), "count"},
		{"low_count", float64(input.LowCount), "count"},
	}
	for _, m := range metrics {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO metrics(scan_id, metric_name, metric_value, metric_unit, category)
			VALUES (?, ?, ?, ?, 'Overall')
		`, scanID, m.name, m.val, m.unit)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *service) GetTrends(accountID string, days int) ([]TrendPoint, error) {
	if days <= 0 {
		days = 30
	}
	query := `
		SELECT
			account_id,
			region,
			DATE(scan_timestamp) as day,
			MAX(total_findings),
			MAX(critical_count),
			MAX(high_count),
			MAX(medium_count),
			MAX(low_count),
			MAX(info_count)
		FROM scans
		WHERE scan_timestamp >= DATETIME('now', ?)
	`
	args := []any{fmt.Sprintf("-%d day", days)}
	if accountID != "" {
		query += " AND account_id=?"
		args = append(args, accountID)
	}
	query += " GROUP BY account_id, region, DATE(scan_timestamp) ORDER BY day ASC, account_id ASC, region ASC"
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	points := []TrendPoint{}
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.AccountID, &p.Region, &p.Date, &p.Total, &p.Critical, &p.High, &p.Medium, &p.Low, &p.Info); err != nil {
			return nil, err
		}
		p.Score = 100 - p.Critical*15 - p.High*8 - p.Medium*3 - p.Low
		if p.Score < 0 {
			p.Score = 0
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

func (s *service) GetRecentScans(accountID string, limit int) ([]ScanSummary, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `
		SELECT scan_id, scan_uuid, account_id, region, scan_timestamp,
			total_findings, critical_count, high_count, medium_count, low_count, info_count, cli_version
		FROM scans
	`
	args := []any{}
	if accountID != "" {
		query += " WHERE account_id=?"
		args = append(args, accountID)
	}
	query += " ORDER BY scan_timestamp DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scans := []ScanSummary{}
	for rows.Next() {
		var ssum ScanSummary
		if err := rows.Scan(&ssum.ScanID, &ssum.ScanUUID, &ssum.AccountID, &ssum.Region, &ssum.ScanTimestamp,
			&ssum.TotalFindings, &ssum.CriticalCount, &ssum.HighCount, &ssum.MediumCount, &ssum.LowCount,
			&ssum.InfoCount, &ssum.Version); err != nil {
			return nil, err
		}
		scans = append(scans, ssum)
	}
	return scans, rows.Err()
}

func (s *service) GetScanComparison(scanID1, scanID2 int64) (*ScanComparison, error) {
	first, err := s.findingHashesByScan(scanID1)
	if err != nil {
		return nil, err
	}
	second, err := s.findingHashesByScan(scanID2)
	if err != nil {
		return nil, err
	}

	firstSet := map[string]bool{}
	secondSet := map[string]bool{}
	for _, h := range first {
		firstSet[h] = true
	}
	for _, h := range second {
		secondSet[h] = true
	}

	cmp := &ScanComparison{ScanID1: scanID1, ScanID2: scanID2}
	for h := range secondSet {
		if !firstSet[h] {
			cmp.NewHashes = append(cmp.NewHashes, h)
		}
	}
	for h := range firstSet {
		if !secondSet[h] {
			cmp.ResolvedHashes = append(cmp.ResolvedHashes, h)
		}
	}
	for h := range firstSet {
		if secondSet[h] {
			cmp.Persistent++
		}
	}
	cmp.NewFindings = len(cmp.NewHashes)
	cmp.Resolved = len(cmp.ResolvedHashes)
	return cmp, nil
}

func (s *service) findingHashesByScan(scanID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT finding_hash FROM scan_findings WHERE scan_id=? AND status='OPEN'`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *service) GetFindingLifecycle(findingHash string) ([]FindingLifecycleEvent, error) {
	rows, err := s.db.Query(`
		SELECT sf.scan_id, s.scan_timestamp, sf.status, sf.severity, sf.category, sf.resource_id
		FROM scan_findings sf
		JOIN scans s ON s.scan_id = sf.scan_id
		WHERE sf.finding_hash=?
		ORDER BY s.scan_timestamp ASC
	`, findingHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FindingLifecycleEvent{}
	for rows.Next() {
		var e FindingLifecycleEvent
		if err := rows.Scan(&e.ScanID, &e.ScanTimestamp, &e.Status, &e.Severity, &e.Category, &e.ResourceID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *service) ListFindings(scanID int64) ([]FindingSnapshot, error) {
	rows, err := s.db.Query(`
		SELECT finding_hash, category, risk_type, severity, resource_id, title, status
		FROM scan_findings WHERE scan_id=? ORDER BY severity DESC
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FindingSnapshot{}
	for rows.Next() {
		var f FindingSnapshot
		if err := rows.Scan(&f.FindingHash, &f.Category, &f.RiskType, &f.Severity, &f.ResourceID, &f.Title, &f.Status); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *service) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "VACUUM")
	return err
}

func (s *service) Reindex(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "REINDEX")
	return err
}

func (s *service) PurgeOlderThan(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, errors.New("days must be > 0")
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM scans WHERE scan_timestamp < DATETIME('now', ?)
	`, fmt.Sprintf("-%d day", days))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *service) Close() error {
	return s.db.Close()
}
