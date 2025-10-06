package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	listenAddrUDP = ":53"
	listenAddrTCP = ":53"
	upstreamUDP   = "100.90.80.129:5353"
	upstreamTCP   = "100.90.80.129:5353"
	readTimeout   = 5 * time.Second
	writeTimeout  = 5 * time.Second
)

type logEntry struct {
	TimeRFC3339 string   `json:"time"`
	ClientIP    string   `json:"client_ip"`
	Protocol    string   `json:"proto"`
	ID          uint16   `json:"id"`
	QName       string   `json:"qname"`
	QType       string   `json:"qtype"`
	RCode       string   `json:"rcode"`
	Answers     []string `json:"answers"`
	RTT         string   `json:"rtt"`
	Error       string   `json:"error,omitempty"`
}

func main() {
	// Start UDP and TCP servers
	udpErrCh := make(chan error, 1)
	tcpErrCh := make(chan error, 1)

	go func() { udpErrCh <- serveUDP() }()
	go func() { tcpErrCh <- serveTCP() }()

	// Block until any server exits
	select {
	case err := <-udpErrCh:
		if err != nil {
			log.Fatalf("UDP server error: %v", err)
		}
	case err := <-tcpErrCh:
		if err != nil {
			log.Fatalf("TCP server error: %v", err)
		}
	}
}

func serveUDP() error {
	pc, err := net.ListenPacket("udp", listenAddrUDP)
	if err != nil {
		return err
	}
	defer pc.Close()

	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}

		// Handle each packet concurrently
		data := make([]byte, n)
		copy(data, buf[:n])
		go func(clientAddr net.Addr, reqBytes []byte) {
			respBytes, rtt, rcode, qname, qtype, answers, id, hErr := forwardUDP(reqBytes)

			entry := logEntry{
				TimeRFC3339: time.Now().Format(time.RFC3339Nano),
				ClientIP:    clientIPFromAddr(clientAddr),
				Protocol:    "udp",
				ID:          id,
				QName:       qname,
				QType:       qtype,
				RCode:       rcode,
				Answers:     answers,
				RTT:         fmt.Sprintf("%.2fms", float64(rtt.Microseconds())/1000.0),
			}
			if hErr != nil {
				entry.Error = hErr.Error()
			}
			logJSON(entry)

			if respBytes != nil {
				_ = writePacket(pc, clientAddr, respBytes)
			}
		}(addr, data)
	}
}

func serveTCP() error {
	ln, err := net.Listen("tcp", listenAddrTCP)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		go handleTCPConn(conn)
	}
}

func handleTCPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readTimeout))
	br := bufio.NewReader(conn)

	// DNS over TCP: 2-byte length prefix
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

	resp, rtt, rcode, qname, qtype, answers, id, hErr := forwardTCP(req)
	entry := logEntry{
		TimeRFC3339: time.Now().Format(time.RFC3339Nano),
		ClientIP:    clientIPFromAddr(conn.RemoteAddr()),
		Protocol:    "tcp",
		ID:          id,
		QName:       qname,
		QType:       qtype,
		RCode:       rcode,
		Answers:     answers,
		RTT:         fmt.Sprintf("%.2fms", float64(rtt.Microseconds())/1000.0),
	}
	if hErr != nil {
		entry.Error = hErr.Error()
	}
	logJSON(entry)

	if resp == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	// Write TCP length prefix + message
	outLen := []byte{byte(len(resp) >> 8), byte(len(resp))}
	if _, err := conn.Write(outLen); err != nil {
		return
	}
	_, _ = conn.Write(resp)
}

func forwardUDP(req []byte) ([]byte, time.Duration, string, string, string, []string, uint16, error) {
	qname, qtype, id := parseQuestion(req)
	// Forward raw packet to upstream via UDP
	raddr, err := net.ResolveUDPAddr("udp", upstreamUDP)
	if err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readTimeout))
	start := time.Now()
	if _, err = conn.Write(req); err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}
	rtt := time.Since(start)
	resp := make([]byte, n)
	copy(resp, buf[:n])

	rcode, answers := parseResponse(resp)
	return resp, rtt, rcode, qname, qtype, answers, id, nil
}

func forwardTCP(req []byte) ([]byte, time.Duration, string, string, string, []string, uint16, error) {
	qname, qtype, id := parseQuestion(req)
	conn, err := net.DialTimeout("tcp", upstreamTCP, readTimeout)
	if err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readTimeout))

	// Write length prefix + message
	if _, err := conn.Write([]byte{byte(len(req) >> 8), byte(len(req))}); err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}

	// Read response length + message
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}
	respLen := int(hdr[0])<<8 | int(hdr[1])
	if respLen <= 0 || respLen > 65535 {
		return nil, 0, "", qname, qtype, nil, id, errors.New("invalid tcp dns length")
	}
	resp := make([]byte, respLen)
	start := time.Now()
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, 0, "", qname, qtype, nil, id, err
	}
	rtt := time.Since(start)

	rcode, answers := parseResponse(resp)
	return resp, rtt, rcode, qname, qtype, answers, id, nil
}

func parseQuestion(msg []byte) (qname string, qtype string, id uint16) {
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

func parseResponse(msg []byte) (rcode string, answers []string) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return "", nil
	}
	rcode = rcodeToString(h.RCode)
	// Skip all questions by iterating until section done
	for {
		_, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return rcode, answers
		}
	}

	// Answers
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

func writePacket(pc net.PacketConn, addr net.Addr, data []byte) error {
	_ = pc.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := pc.WriteTo(data, addr)
	return err
}

func logJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		log.Printf("marshal log error: %v", err)
		return
	}
	log.Println(string(b))
}

// Prevent unused import complaints in case of future expansion
var _ = context.Background
