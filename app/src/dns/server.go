package dns

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

type DnsLogObj struct {
	TimeRFC3339 string   `json:"time"`
	ClientIP    string   `json:"client_ip"`
	CountryZH   string   `json:"country"`
	Protocol    string   `json:"proto"`
	ID          uint16   `json:"id"`
	QName       string   `json:"qname"`
	QType       string   `json:"qtype"`
	RCode       string   `json:"rcode"`
	Answers     []string `json:"answers"`
	RTT         string   `json:"rtt"`
	Blocked     bool     `json:"blocked,omitempty"`
	Error       string   `json:"error,omitempty"`
}

type Options struct {
	ListenUDP    string
	ListenTCP    string
	UpstreamUDP  string
	UpstreamTCP  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	EnvPath      string
	Logger       *zap.Logger
}

type server struct {
	listenUDP    string
	listenTCP    string
	upstreamUDP  string
	upstreamTCP  string
	readTimeout  time.Duration
	writeTimeout time.Duration
	blockMgr     *BlockManager
	logger       *zap.Logger
	db           *sql.DB
	logDir       string
	curFile      *os.File
	curDate      string
}

// Start launches UDP and TCP DNS listeners. Handles logging internally.
func Start(ctx context.Context, opts Options, db *sql.DB, logDir string) error {
	bm := NewBlockManager(opts.EnvPath)
	stopCh := make(chan struct{})
	bm.StartScheduler(stopCh)

	s := &server{
		listenUDP:    opts.ListenUDP,
		listenTCP:    opts.ListenTCP,
		upstreamUDP:  opts.UpstreamUDP,
		upstreamTCP:  opts.UpstreamTCP,
		readTimeout:  opts.ReadTimeout,
		writeTimeout: opts.WriteTimeout,
		blockMgr:     bm,
		logger:       opts.Logger,
		db:           db,
		logDir:       logDir,
	}

	udpErrCh := make(chan error, 1)
	tcpErrCh := make(chan error, 1)

	go func() { udpErrCh <- s.serveUDP(ctx) }()
	go func() { tcpErrCh <- s.serveTCP(ctx) }()

	select {
	case <-ctx.Done():
		close(stopCh)
		return ctx.Err()
	case err := <-udpErrCh:
		close(stopCh)
		return err
	case err := <-tcpErrCh:
		close(stopCh)
		return err
	}
}

func (s *server) serveUDP(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.listenUDP)
	if err != nil {
		return err
	}
	defer pc.Close()

	buf := make([]byte, 4096)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(s.readTimeout))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			return err
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go func(clientAddr net.Addr, reqBytes []byte) {
			clientIP := clientIPFromAddr(clientAddr)
			// GeoIP country check
			var countryZH string
			if s.blockMgr != nil {
				allowed, _, zh := s.blockMgr.IsClientAllowed(clientIP)
				countryZH = zh
				if !allowed {
					// Block by country: return NXDOMAIN immediately
					resp, _ := buildNXDomainResponse(reqBytes)
					entry := DnsLogObj{
						TimeRFC3339: time.Now().Format(time.RFC3339Nano),
						ClientIP:    clientIP,
						CountryZH:   countryZH,
						Protocol:    "udp",
						ID:          0,
						QName:       "",
						QType:       "",
						RCode:       "NXDOMAIN",
						Answers:     nil,
						RTT:         "0.00ms",
						Blocked:     true,
					}
					if s.logger != nil {
						entryJSON, _ := json.Marshal(entry)
						s.logger.Info(string(entryJSON))
					}
					if resp != nil {
						_ = s.writePacket(pc, clientAddr, resp)
					}
					return
				}
			}
			respBytes, rtt, rcode, qname, qtype, answers, id, wasBlocked, hErr := s.forwardUDP(reqBytes)
			entry := DnsLogObj{
				TimeRFC3339: time.Now().Format(time.RFC3339Nano),
				ClientIP:    clientIP,
				CountryZH:   countryZH,
				Protocol:    "udp",
				ID:          id,
				QName:       qname,
				QType:       qtype,
				RCode:       rcode,
				Answers:     answers,
				RTT:         fmt.Sprintf("%.2fms", float64(rtt.Microseconds())/1000.0),
				Blocked:     wasBlocked,
			}
			if hErr != nil {
				entry.Error = hErr.Error()
			}
			s.handleDNSLog(entry)
			if respBytes != nil {
				_ = s.writePacket(pc, clientAddr, respBytes)
			}
		}(addr, data)
	}
}

func (s *server) serveTCP(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenTCP)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(s.readTimeout))
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			return err
		}
		go s.handleTCPConn(conn)
	}
}

func (s *server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))
	br := bufio.NewReader(conn)
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, lengthBytes); err != nil {
		return
	}
	msgLen := int(lengthBytes[0])<<8 | int(lengthBytes[1])
	if msgLen <= 0 || msgLen > 65535 {
		return
	}
	req := make([]byte, msgLen)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}

	// GeoIP country check
	clientIP := clientIPFromAddr(conn.RemoteAddr())
	var countryZH string
	if s.blockMgr != nil {
		allowed, _, zh := s.blockMgr.IsClientAllowed(clientIP)
		countryZH = zh
		if !allowed {
			resp, _ := buildNXDomainResponse(req)
			entry := DnsLogObj{
				TimeRFC3339: time.Now().Format(time.RFC3339Nano),
				ClientIP:    clientIP,
				CountryZH:   countryZH,
				Protocol:    "tcp",
				ID:          0,
				QName:       "",
				QType:       "",
				RCode:       "NXDOMAIN",
				Answers:     nil,
				RTT:         "0.00ms",
				Blocked:     true,
			}
			s.handleDNSLog(entry)
			if resp != nil {
				_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
				outLen := []byte{byte(len(resp) >> 8), byte(len(resp))}
				if _, err := conn.Write(outLen); err == nil {
					_, _ = conn.Write(resp)
				}
			}
			return
		}
	}
	resp, rtt, rcode, qname, qtype, answers, id, wasBlocked, hErr := s.forwardTCP(req)
	entry := DnsLogObj{
		TimeRFC3339: time.Now().Format(time.RFC3339Nano),
		ClientIP:    clientIP,
		CountryZH:   countryZH,
		Protocol:    "tcp",
		ID:          id,
		QName:       qname,
		QType:       qtype,
		RCode:       rcode,
		Answers:     answers,
		RTT:         fmt.Sprintf("%.2fms", float64(rtt.Microseconds())/1000.0),
		Blocked:     wasBlocked,
	}
	if hErr != nil {
		entry.Error = hErr.Error()
	}
	s.handleDNSLog(entry)
	if resp == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	outLen := []byte{byte(len(resp) >> 8), byte(len(resp))}
	if _, err := conn.Write(outLen); err != nil {
		return
	}
	_, _ = conn.Write(resp)
}

func (s *server) forwardUDP(req []byte) ([]byte, time.Duration, string, string, string, []string, uint16, bool, error) {
	qname, qtype, id := s.parseQuestion(req)
	if s.blockMgr != nil && qname != "" {
		q := strings.TrimSuffix(qname, ".")
		if s.blockMgr.IsWhitelisted(q) {
		} else if s.blockMgr.IsBlocked(q) {
			resp, err := buildNXDomainResponse(req)
			if err != nil {
				return nil, 0, "", qname, qtype, nil, id, true, err
			}
			return resp, 0, "NXDOMAIN", qname, qtype, nil, id, true, nil
		}
	}
	raddr, err := net.ResolveUDPAddr("udp", s.upstreamUDP)
	if err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))
	start := time.Now()
	if _, err = conn.Write(req); err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	rtt := time.Since(start)
	resp := make([]byte, n)
	copy(resp, buf[:n])
	rcode, answers := s.parseResponse(resp)
	return resp, rtt, rcode, qname, qtype, answers, id, false, nil
}

func (s *server) forwardTCP(req []byte) ([]byte, time.Duration, string, string, string, []string, uint16, bool, error) {
	qname, qtype, id := s.parseQuestion(req)
	if s.blockMgr != nil && qname != "" {
		q := strings.TrimSuffix(qname, ".")
		if s.blockMgr.IsWhitelisted(q) {
		} else if s.blockMgr.IsBlocked(q) {
			resp, err := buildNXDomainResponse(req)
			if err != nil {
				return nil, 0, "", qname, qtype, nil, id, true, err
			}
			return resp, 0, "NXDOMAIN", qname, qtype, nil, id, true, nil
		}
	}
	conn, err := net.DialTimeout("tcp", s.upstreamTCP, s.readTimeout)
	if err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))
	if _, err := conn.Write([]byte{byte(len(req) >> 8), byte(len(req))}); err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	respLen := int(hdr[0])<<8 | int(hdr[1])
	if respLen <= 0 || respLen > 65535 {
		return nil, 0, "", qname, qtype, nil, id, false, errors.New("invalid tcp dns length")
	}
	resp := make([]byte, respLen)
	start := time.Now()
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, 0, "", qname, qtype, nil, id, false, err
	}
	rtt := time.Since(start)
	rcode, answers := s.parseResponse(resp)
	return resp, rtt, rcode, qname, qtype, answers, id, false, nil
}

func (s *server) parseQuestion(msg []byte) (qname string, qtype string, id uint16) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return "", "", 0
	}
	id = h.ID
	q, err := p.Question()
	if err != nil {
		return "", "", id
	}
	qname = q.Name.String()
	qtype = typeToString(q.Type)
	return
}

func (s *server) parseResponse(msg []byte) (rcode string, answers []string) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return "", nil
	}
	rcode = rcodeToString(h.RCode)
	for {
		_, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return rcode, answers
		}
	}
	for {
		a, err := p.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			break
		}
		answers = append(answers, rrToString(a))
	}
	return
}

func (s *server) writePacket(pc net.PacketConn, addr net.Addr, data []byte) error {
	_ = pc.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	_, err := pc.WriteTo(data, addr)
	return err
}

func MarshalAnswers(answers []string) string {
	b, _ := json.Marshal(answers)
	return string(b)
}

// handleDNSLog 处理DNS查询日志，同时写入数据库和文件
func (s *server) handleDNSLog(log DnsLogObj) {
	// 写入数据库
	s.insertQueryLog(log)

	// 写入文件
	s.writeJSONLog(log)
}

// insertQueryLog 将DNS查询日志插入数据库
func (s *server) insertQueryLog(log DnsLogObj) {
	if s.db == nil {
		return
	}

	rttMs := 0.0
	if log.RTT != "" {
		// format like "1.23ms"
		var v float64
		_, _ = fmt.Sscanf(log.RTT, "%fms", &v)
		rttMs = v
	}

	query := `INSERT INTO query_logs (time_rfc3339, client_ip, country, proto, qid, qname, qtype, rcode, answers, rtt_ms, blocked, error) 
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(query,
		log.TimeRFC3339,
		log.ClientIP,
		log.CountryZH,
		log.Protocol,
		int64(log.ID),
		log.QName,
		log.QType,
		log.RCode,
		MarshalAnswers(log.Answers),
		rttMs,
		log.Blocked,
		log.Error,
	)

	if err != nil {
		s.logger.Error("插入查询日志失败", zap.Error(err))
	}
}

// writeJSONLog 将DNS查询日志写入JSON文件
func (s *server) writeJSONLog(log DnsLogObj) {
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
	_ = enc.Encode(log)
}

// rotateByDay 按日期轮转日志文件
func (s *server) rotateByDay(date string) {
	_ = s.closeCur()
	s.curDate = date
	s.cleanupOldDays(3)

	// 使用dns-前缀和日期时间格式，Windows兼容（替换冒号为连字符）
	path := filepath.Join(s.logDir, "dns-"+date+"T00-00-00.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		// 如果日志目录不存在，尝试创建
		if os.IsNotExist(err) {
			os.MkdirAll(s.logDir, 0755)
			f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		}
	}
	if err == nil {
		s.curFile = f
	}
}

// rotateBySize 按大小轮转日志文件
func (s *server) rotateBySize() {
	if s.curFile == nil {
		return
	}
	_ = s.curFile.Close()
	base := filepath.Join(s.logDir, "dns-"+s.curDate+"T00-00-00.json")
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

// cleanupOldDays 清理旧的日志文件
func (s *server) cleanupOldDays(keep int) {
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
		if len(name) < len("dns-2006-01-02T00-00-00.json") {
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

// closeCur 关闭当前日志文件
func (s *server) closeCur() error {
	if s.curFile != nil {
		err := s.curFile.Close()
		s.curFile = nil
		return err
	}
	return nil
}
