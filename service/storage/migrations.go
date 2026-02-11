package storage

const schemaV1 = `
CREATE TABLE IF NOT EXISTS scans (
    scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_uuid       TEXT UNIQUE NOT NULL,
    account_id      TEXT NOT NULL,
    region          TEXT NOT NULL,
    scan_timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
    scan_duration   INTEGER,
    total_findings  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    cli_version     TEXT,
    scan_profile    TEXT,
    scan_flags      TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_account_timestamp
    ON scans(account_id, scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp
    ON scans(scan_timestamp DESC);

CREATE TABLE IF NOT EXISTS findings (
    finding_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      TEXT NOT NULL,
    region          TEXT NOT NULL,
    finding_hash    TEXT NOT NULL,
    category        TEXT NOT NULL,
    subcategory     TEXT,
    risk_type       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    resource_type   TEXT,
    resource_id     TEXT,
    resource_arn    TEXT,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    recommendation  TEXT,
    compliance_tags TEXT,
    first_seen      DATETIME NOT NULL,
    last_seen       DATETIME NOT NULL,
    resolved_at     DATETIME,
    status          TEXT DEFAULT 'OPEN',
    UNIQUE(account_id, finding_hash)
);

CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(finding_hash);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);

CREATE TABLE IF NOT EXISTS scan_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL,
    finding_hash   TEXT NOT NULL,
    severity       TEXT NOT NULL,
    status         TEXT NOT NULL,
    category       TEXT NOT NULL,
    risk_type      TEXT NOT NULL,
    resource_id    TEXT,
    title          TEXT NOT NULL,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_hash ON scan_findings(finding_hash);

CREATE TABLE IF NOT EXISTS metrics (
    metric_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    metric_name     TEXT NOT NULL,
    metric_value    REAL NOT NULL,
    metric_unit     TEXT,
    category        TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_metrics_scan ON metrics(scan_id);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name);

CREATE TABLE IF NOT EXISTS compliance_scores (
    score_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    framework       TEXT NOT NULL,
    version         TEXT,
    score           REAL NOT NULL,
    passed_checks   INTEGER DEFAULT 0,
    failed_checks   INTEGER DEFAULT 0,
    not_applicable  INTEGER DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_compliance_scan ON compliance_scores(scan_id);
CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_scores(framework);
`
