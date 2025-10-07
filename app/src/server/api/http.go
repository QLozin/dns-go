package api

import (
	"database/sql"
	"dnsgolang/app/src/server/service"
	"net/http"

	"github.com/labstack/echo/v4"
)

type API struct{ svc *service.Service }

func New(e *echo.Echo, svc *service.Service) *API {
	a := &API{svc: svc}
	e.GET("/api/logs", a.getLogs)
	e.GET("/api/top-clients", a.getTopClients)
	e.GET("/api/blocked-stats", a.getBlockedStats)
	return a
}

func (a *API) getLogs(c echo.Context) error {
	rows, err := a.svc.ListLogs(500)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer rows.Close()
	type row struct {
		Time     string  `json:"time"`
		ClientIP string  `json:"client_ip"`
		Country  string  `json:"country"`
		Proto    string  `json:"proto"`
		QID      int64   `json:"id"`
		QName    string  `json:"qname"`
		QType    string  `json:"qtype"`
		RCode    string  `json:"rcode"`
		Answers  string  `json:"answers"`
		RTTms    float64 `json:"rtt_ms"`
		Blocked  bool    `json:"blocked"`
		Error    string  `json:"error"`
	}
	var out []row
	for rows.Next() {
		var r row
		var errStr sql.NullString
		var blockedInt int
		if err := rows.Scan(&r.Time, &r.ClientIP, &r.Country, &r.Proto, &r.QID, &r.QName, &r.QType, &r.RCode, &r.Answers, &r.RTTms, &blockedInt, &errStr); err != nil {
			return err
		}
		r.Blocked = blockedInt == 1
		if errStr.Valid {
			r.Error = errStr.String
		}
		out = append(out, r)
	}
	return c.JSON(http.StatusOK, out)
}

func (a *API) getTopClients(c echo.Context) error {
	rows, err := a.svc.TopClients24h()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer rows.Close()
	type row struct {
		ClientIP string `json:"client_ip"`
		Country  string `json:"country"`
		Count    int64  `json:"count"`
	}
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ClientIP, &r.Country, &r.Count); err != nil {
			return err
		}
		out = append(out, r)
	}
	return c.JSON(http.StatusOK, out)
}

func (a *API) getBlockedStats(c echo.Context) error {
	rows, err := a.svc.BlockedStatsAll()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer rows.Close()
	type row struct {
		QName   string `json:"qname"`
		Country string `json:"country"`
		Count   int64  `json:"count"`
	}
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.QName, &r.Country, &r.Count); err != nil {
			return err
		}
		out = append(out, r)
	}
	return c.JSON(http.StatusOK, out)
}
