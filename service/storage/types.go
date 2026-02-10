package storage

import (
	"context"
	"time"
)

// Service defines persistence and trend query operations.
type Service interface {
	SaveScan(ctx context.Context, input SaveScanInput) (int64, error)
	GetTrends(accountID string, days int) ([]TrendPoint, error)
	GetRecentScans(accountID string, limit int) ([]ScanSummary, error)
	GetScanComparison(scanID1, scanID2 int64) (*ScanComparison, error)
	GetFindingLifecycle(findingHash string) ([]FindingLifecycleEvent, error)
	ListFindings(scanID int64) ([]FindingSnapshot, error)
	Vacuum(ctx context.Context) error
	Reindex(ctx context.Context) error
	PurgeOlderThan(ctx context.Context, days int) (int64, error)
	Close() error
}

// SaveScanInput is the payload saved for a completed scan.
type SaveScanInput struct {
	ScanUUID      string
	AccountID     string
	Region        string
	DurationSec   int64
	Version       string
	Profile       string
	FlagsJSON     string
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
	Findings      []Finding
}

// Finding is a normalized finding used for storage and lifecycle tracking.
type Finding struct {
	Hash           string
	Category       string
	Subcategory    string
	RiskType       string
	Severity       string
	ResourceType   string
	ResourceID     string
	ResourceARN    string
	Title          string
	Description    string
	Recommendation string
	ComplianceTags string
}

// TrendPoint is a daily aggregate for trend visualizations.
type TrendPoint struct {
	Region    string `json:"region"`
	Date      string `json:"date"`
	Total     int    `json:"total"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
	Medium    int    `json:"medium"`
	Low       int    `json:"low"`
	Info      int    `json:"info"`
	OpenCount int    `json:"open_count"`
	Score     int    `json:"score"`
}

// ScanSummary provides compact scan metadata.
type ScanSummary struct {
	ScanID        int64
	ScanUUID      string
	AccountID     string
	Region        string
	ScanTimestamp time.Time
	TotalFindings int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
	Version       string
}

// ScanComparison holds diff details between two scans.
type ScanComparison struct {
	ScanID1        int64
	ScanID2        int64
	NewFindings    int
	Resolved       int
	Persistent     int
	NewHashes      []string
	ResolvedHashes []string
}

// FindingLifecycleEvent represents finding status at a given scan timestamp.
type FindingLifecycleEvent struct {
	ScanID        int64
	ScanTimestamp time.Time
	Status        string
	Severity      string
	Category      string
	ResourceID    string
}

// FindingSnapshot is a scan-time finding view.
type FindingSnapshot struct {
	FindingHash string
	Category    string
	RiskType    string
	Severity    string
	ResourceID  string
	Title       string
	Status      string
}
