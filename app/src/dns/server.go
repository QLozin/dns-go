package dns

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	onLog        func(DnsLogObj)
	logger       *zap.Logger
}

// Start launches UDP and TCP DNS listeners. Calls onLog for every query handled.
func Start(ctx context.Context, opts Options, onLog func(DnsLogObj)) error {
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
		onLog:        onLog,
		logger:       opts.Logger,
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
			if s.onLog != nil {
				s.onLog(entry)
			}
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
			if s.onLog != nil {
				s.onLog(entry)
			}
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
	if s.onLog != nil {
		s.onLog(entry)
	}
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
