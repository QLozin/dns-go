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
}

func (s *Service) ListLogs(limit int) (*sql.Rows, error) { return s.db.ListQueryLogs(limit) }

func (s *Service) TopClients24h() (*sql.Rows, error) {
	return s.db.TopClientsSince(time.Now().Add(-24*time.Hour), 10)
}

func (s *Service) BlockedStatsAll() (*sql.Rows, error) { return s.db.BlockedStatsAll() }
