package service

import (
	"database/sql"
	d "dnsgolang/app/src/dns"
	"dnsgolang/app/src/server/infra"
	"fmt"
	"time"
)

type Service struct{ db *infra.DB }

func New(db *infra.DB) *Service { return &Service{db: db} }

func (s *Service) HandleDNSLog(le d.LogEntry) {
	rttMs := 0.0
	if le.RTT != "" {
		// format like "1.23ms"
		var v float64
		_, _ = fmt.Sscanf(le.RTT, "%fms", &v)
		rttMs = v
	}
	_ = s.db.InsertQueryLog(infra.QueryLogRow{
		TimeRFC3339: le.TimeRFC3339,
		ClientIP:    le.ClientIP,
		Proto:       le.Protocol,
		QID:         int64(le.ID),
		QName:       le.QName,
		QType:       le.QType,
		RCode:       le.RCode,
		Answers:     d.MarshalAnswers(le.Answers),
		RTTms:       rttMs,
		Blocked:     le.Blocked,
		Error:       sql.NullString{String: le.Error, Valid: le.Error != ""},
	})
}

func (s *Service) ListLogs(limit int) (*sql.Rows, error) { return s.db.ListQueryLogs(limit) }

func (s *Service) TopClients24h() (*sql.Rows, error) {
	return s.db.TopClientsSince(time.Now().Add(-24*time.Hour), 10)
}

func (s *Service) BlockedStatsAll() (*sql.Rows, error) { return s.db.BlockedStatsAll() }
