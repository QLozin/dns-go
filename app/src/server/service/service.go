package service

import (
	"database/sql"
	d "dnsgolang/app/src/dns"
	"dnsgolang/app/src/server/infra"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

type Service struct {
	db      *infra.DB
	logDir  string
	curFile *os.File
	curDate string
	logger  *zap.Logger
}

func New(db *infra.DB) *Service {
	return &Service{db: db, logger: zap.NewNop()}
}

func NewWithLogDir(db *infra.DB, dir string) *Service {
	if dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	return &Service{db: db, logDir: dir, logger: zap.NewNop()}
}

func NewWithLogger(db *infra.DB, logger *zap.Logger) *Service {
	return &Service{db: db, logger: logger}
}

func (s *Service) HandleDNSLog(log d.DnsLogObj) {
	rttMs := 0.0
	if log.RTT != "" {
		// format like "1.23ms"
		var v float64
		_, _ = fmt.Sscanf(log.RTT, "%fms", &v)
		rttMs = v
	}
	_ = s.db.InsertQueryLog(infra.QueryLogRow{
		TimeRFC3339: log.TimeRFC3339,
		ClientIP:    log.ClientIP,
		Country:     log.CountryZH,
		Proto:       log.Protocol,
		QID:         int64(log.ID),
		QName:       log.QName,
		QType:       log.QType,
		RCode:       log.RCode,
		Answers:     d.MarshalAnswers(log.Answers),
		RTTms:       rttMs,
		Blocked:     log.Blocked,
		Error:       sql.NullString{String: log.Error, Valid: log.Error != ""},
	})

	// best-effort file logging
	s.writeJSONLog(log)
}

func (s *Service) ListLogs(limit int) (*sql.Rows, error) { return s.db.ListQueryLogs(limit) }

func (s *Service) TopClients24h() (*sql.Rows, error) {
	return s.db.TopClientsSince(time.Now().Add(-24*time.Hour), 10)
}

func (s *Service) BlockedStatsAll() (*sql.Rows, error) { return s.db.BlockedStatsAll() }

// ---- file logging ----
func (s *Service) writeJSONLog(l d.DnsLogObj) {
	if s.logDir == "" {
		return
	}
	today := time.Now().Format("2006-01-02")
	if s.curDate != today || s.curFile == nil {
		s.rotateByDay(today)
	}
	if s.curFile == nil {
		return
	}
	// rotate by size 10MB
	if fi, err := s.curFile.Stat(); err == nil && fi.Size() >= 10*1024*1024 {
		s.rotateBySize()
	}
	enc := json.NewEncoder(s.curFile)
	_ = enc.Encode(l)
}

func (s *Service) rotateByDay(date string) {
	_ = s.closeCur()
	s.curDate = date
	s.cleanupOldDays(3)
	// 使用dns-前缀和日期时间格式
	path := filepath.Join(s.logDir, "dns-"+date+" 00:00:00.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		s.curFile = f
	}
}

func (s *Service) rotateBySize() {
	if s.curFile == nil {
		return
	}
	_ = s.curFile.Close()
	base := filepath.Join(s.logDir, "dns-"+s.curDate+" 00:00:00.json")
	// next index
	idx := 1
	for {
		cand := fmt.Sprintf("%s.%d", base, idx)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			break
		}
		idx++
	}
	_ = os.Rename(base, fmt.Sprintf("%s.%d", base, idx))
	f, err := os.OpenFile(base, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		s.curFile = f
	}
}

func (s *Service) cleanupOldDays(keep int) {
	if keep <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -keep)
	entries, err := os.ReadDir(s.logDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) < len("dns-2006-01-02 00:00:00.json") {
			continue
		}
		// 匹配dns-前缀的日期格式
		if len(name) >= 10 && name[:4] == "dns-" {
			dateStr := name[4:14] // 提取日期部分
			if t, err := time.Parse("2006-01-02", dateStr); err == nil {
				if t.Before(cutoff) {
					_ = os.Remove(filepath.Join(s.logDir, name))
				}
			}
		}
	}
}

func (s *Service) closeCur() error {
	if s.curFile != nil {
		err := s.curFile.Close()
		s.curFile = nil
		return err
	}
	return nil
}
