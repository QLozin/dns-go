package server

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

// DB 封装 SQLite 数据库连接和操作
type DB struct {
	*DBOptions
	db *sql.DB
}

func NewDB(config *DBOptions) (*DB, error) {
	db := &DB{
		DBOptions: config,
		db:        nil,
	}
	if int(db.DBConfig.MaxConnections) <= 0 {
		db.DBConfig.MaxConnections = 1
	}
	sqliteFile := db.DBConfig.SqlitePath
	if info, err := os.Stat(sqliteFile); os.IsNotExist(err) {
		_, createErr := os.Create(sqliteFile)
		if createErr != nil {
			return nil, fmt.Errorf("创建数据库文件失败: %w", createErr)
		}
	} else if info.IsDir() {
		return nil, fmt.Errorf("数据库文件路径不能是目录: %s", sqliteFile)
	}
	if err := db.Open(); err != nil {
		return nil, err
	}
	return db, nil
}

// Open 打开 SQLite 数据库连接并执行迁移
func (d *DB) Open() error {
	maxConns := int(d.DBConfig.MaxConnections)
	sqlitePath := d.DBConfig.SqlitePath

	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return fmt.Errorf("打开数据库失败: %w", err)
	}
	db.SetMaxOpenConns(maxConns)

	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		db.Close()
		// 基础设施层：数据库配置失败是系统错误，记录 Error
		if d.Logger != nil {
			d.Logger.Error("设置数据库WAL模式失败",
				zap.String("sqlitePath", sqlitePath),
				zap.Error(err))
		}
		return fmt.Errorf("设置 WAL 模式失败: %w", err)
	}
	d.db = db
	if err := d.migrate(); err != nil {
		db.Close()
		d.db = nil
		// 基础设施层：数据库迁移失败是系统错误，记录 Error
		if d.Logger != nil {
			d.Logger.Error("数据库迁移失败",
				zap.String("sqlitePath", sqlitePath),
				zap.Error(err))
		}
		return fmt.Errorf("数据库迁移失败: %w", err)
	}

	return nil
}

func (d *DB) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

func (d *DB) migrate() error {
	db := d.db
	if err := createDnsLogTable(db); err != nil {
		return fmt.Errorf("创建表结构失败: %w", err)
	}
	return nil
}

func createDnsLogTable(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS query_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  time TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  geo_country TEXT,
  protocol TEXT NOT NULL,
  msg_id INTEGER NOT NULL,
  qname TEXT NOT NULL,
  qtype TEXT NOT NULL,
  rcode TEXT NOT NULL,
  answers TEXT,
  rtt_ms REAL,
  blocked INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  upstream_dns TEXT
);
CREATE INDEX IF NOT EXISTS idx_query_logs_time ON query_logs(time);
CREATE INDEX IF NOT EXISTS idx_query_logs_client ON query_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_query_logs_qname ON query_logs(qname);
`)
	if err != nil {
		return err
	}
	return nil
}

func (d *DB) InsertDnsLog(log DnsLog) error {
	db := d.db
	if db == nil {
		return fmt.Errorf("数据库连接未初始化")
	}

	// 验证并规范化时间格式
	timeStr := normalizeTime(log.Time)
	if timeStr == "" {
		return fmt.Errorf("时间格式无效: %s", log.Time)
	}

	// 解析 RTT 字符串为浮点数
	rttMs := parseRTT(log.RTT)

	// 准备插入 SQL - 字段名使用小写下划线，保持与结构体字段名一致
	query := `INSERT INTO query_logs (time, client_ip, geo_country, protocol, msg_id, qname, qtype, rcode, answers, rtt_ms, blocked, error, upstream_dns) 
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query,
		timeStr,                          // time (RFC3339Nano格式)
		log.ClientIP,                     // client_ip
		nullEmptyString(log.GeoCountry),  // geo_country
		log.Protocol,                     // protocol
		int64(log.MsgId),                 // msg_id
		log.QName,                        // qname
		log.QType,                        // qtype
		log.RCode,                        // rcode
		nullEmptyString(log.Answers),     // answers
		rttMs,                            // rtt_ms
		boolToInt(log.Blocked),           // blocked
		nullEmptyString(log.Error),       // error
		nullEmptyString(log.UpstreamDNS), // upstream_dns
	)

	if err != nil {
		if d.Logger != nil {
			d.Logger.Error("插入DNS日志失败", zap.Error(err), zap.Any("dnslog", log))
		}
		return fmt.Errorf("插入DNS日志失败: %w", err)
	}

	return nil
}

// parseRTT 解析 RTT 字符串（格式: "X.XXms"）为 float64
func parseRTT(rtt string) float64 {
	if rtt == "" {
		return 0.0
	}
	var v float64
	_, err := fmt.Sscanf(rtt, "%fms", &v)
	if err != nil {
		return 0.0
	}
	return v
}

// normalizeTime 确保时间格式为 RFC3339Nano
// 如果输入已经是 RFC3339Nano 格式，直接返回
// 否则尝试解析并转换为 RFC3339Nano 格式
func normalizeTime(timeStr string) string {
	if timeStr == "" {
		return ""
	}

	// 尝试解析为 RFC3339Nano
	if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
		return t.Format(time.RFC3339Nano)
	}

	// 尝试解析为 RFC3339
	if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
		return t.Format(time.RFC3339Nano)
	}

	// 尝试解析为常见的日期时间格式
	formats := []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05Z07:00",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t.Format(time.RFC3339Nano)
		}
	}

	// 如果都无法解析，返回空字符串（会在 InsertDnsLog 中被检测到）
	return ""
}

// nullEmptyString 将空字符串转换为 nil（用于 SQL NULL）
func nullEmptyString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// boolToInt 将 bool 转换为 int (true -> 1, false -> 0)
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
