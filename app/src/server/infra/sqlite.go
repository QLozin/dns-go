package infra

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct{ *sql.DB }

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS query_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  time_rfc3339 TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  country TEXT,
  proto TEXT NOT NULL,
  qid INTEGER NOT NULL,
  qname TEXT NOT NULL,
  qtype TEXT NOT NULL,
  rcode TEXT NOT NULL,
  answers TEXT,
  rtt_ms REAL,
  blocked INTEGER NOT NULL DEFAULT 0,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_query_logs_time ON query_logs(time_rfc3339);
CREATE INDEX IF NOT EXISTS idx_query_logs_client ON query_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_query_logs_qname ON query_logs(qname);
`)
	if err != nil {
		return err
	}
	// Try to add column if table already existed without country
	_, _ = db.Exec(`ALTER TABLE query_logs ADD COLUMN country TEXT;`)
	return nil
}

type QueryLogRow struct {
	TimeRFC3339 string
	ClientIP    string
	Country     string
	Proto       string
	QID         int64
	QName       string
	QType       string
	RCode       string
	Answers     string
	RTTms       float64
	Blocked     bool
	Error       sql.NullString
}

func (db *DB) InsertQueryLog(r QueryLogRow) error {
	_, err := db.Exec(`INSERT INTO query_logs(time_rfc3339, client_ip, country, proto, qid, qname, qtype, rcode, answers, rtt_ms, blocked, error)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.TimeRFC3339, r.ClientIP, nullEmpty(r.Country), r.Proto, r.QID, r.QName, r.QType, r.RCode, r.Answers, r.RTTms, boolToInt(r.Blocked), nullStr(r.Error))
	return err
}

func (db *DB) ListQueryLogs(limit int) (*sql.Rows, error) {
	if limit <= 0 {
		limit = 200
	}
	return db.Query(`SELECT time_rfc3339, client_ip, country, proto, qid, qname, qtype, rcode, answers, rtt_ms, blocked, error FROM query_logs ORDER BY id DESC LIMIT ?`, limit)
}

func (db *DB) TopClientsSince(since time.Time, limit int) (*sql.Rows, error) {
	if limit <= 0 {
		limit = 10
	}
	return db.Query(`
        SELECT client_ip, COALESCE(country,'') as country, COUNT(1) as cnt
        FROM query_logs
        WHERE time_rfc3339 >= ?
        GROUP BY client_ip, country
        ORDER BY cnt DESC
        LIMIT ?
    `, since.Format(time.RFC3339Nano), limit)
}

func (db *DB) BlockedStatsAll() (*sql.Rows, error) {
	return db.Query(`
        SELECT qname, COALESCE(country,'') as country, COUNT(1) as cnt
        FROM query_logs
        WHERE blocked=1
        GROUP BY qname, country
        ORDER BY cnt DESC
    `)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func nullStr(s sql.NullString) any {
	if s.Valid {
		return s.String
	}
	return nil
}

func nullEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
