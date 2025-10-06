package main

import (
	"os"
	"sync"
	"time"
)

// DNSHeader 表示DNS消息头
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSQuestion 表示DNS查询部分
type DNSQuestion struct {
	Name   string
	QType  uint16
	QClass uint16
}

// DNSRecord 表示DNS记录
type DNSRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	rdata    []byte
}

// DNSLogEntry 表示DNS查询日志条目
type DNSLogEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	ClientIP      string    `json:"client_ip"`
	TransactionID uint16    `json:"transaction_id"`
	DomainName    string    `json:"domain_name"`
	QueryType     uint16    `json:"query_type"`
	QueryClass    uint16    `json:"query_class"`
	Result        string    `json:"result"`
}

var (
	logFile     *os.File
	logMutex    sync.Mutex
	upstreamDNS = "100.90.80.129:5353"
)
