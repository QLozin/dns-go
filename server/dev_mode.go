package server

import (
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

// hasDevMode 检查是否启用了指定的开发模式
func (s *Server) hasDevMode(mode string) bool {
	for _, m := range s.DevModes {
		if m == mode {
			return true
		}
	}
	return false
}

// buildDefaultAResponse 构造一个默认的DNS响应，所有请求的域名都返回 127.127.127.127
func (s *Server) buildDefaultAResponse(headerID uint16, question dnsmessage.Question) ([]byte, error) {
	// 解析目标IP地址 127.127.127.127
	ip := net.ParseIP("127.127.127.127")
	if ip == nil {
		return nil, fmt.Errorf("无效的IP地址: 127.127.127.127")
	}

	// 将IPv4地址转换为[4]byte格式
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("IP地址不是有效的IPv4地址")
	}

	// 构造DNS消息
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 headerID,
			Response:           true,
			Authoritative:      false,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: []dnsmessage.Question{question},
	}

	// 构造A记录资源
	aResource := dnsmessage.AResource{
		A: [4]byte{ipv4[0], ipv4[1], ipv4[2], ipv4[3]},
	}

	// 添加Answer部分
	msg.Answers = []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{
				Name:  question.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   300, // 5分钟TTL
			},
			Body: &aResource,
		},
	}

	// 打包消息
	return msg.Pack()
}

// handleDevModeHook 处理hook模式：在forward时返回127.127.127.127
// 仅在shouldForward为true时执行
func (s *Server) handleDevModeHook(headerID uint16, question dnsmessage.Question, clientAddr net.Addr, packet net.PacketConn, clientIP net.IP, traceId int, qname, qtype string) (bool, error) {
	if !s.hasDevMode("hook") {
		return false, nil
	}

	// 构造默认IP响应
	respBytes, err := s.buildDefaultAResponse(headerID, question)
	if err != nil {
		s.Logger.Error("构造默认IP响应失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.Int("traceId", traceId))
		return true, err
	}

	// 记录日志
	dnslog := DnsLog{
		Time:        TimeNow(),
		Protocol:    "udp",
		RCode:       "NOERROR",
		Blocked:     false,
		RTT:         "0.00ms",
		QName:       qname,
		QType:       qtype,
		MsgId:       traceId,
		ClientIP:    clientIP.String(),
		UpstreamDNS: "dev-mode-hook",
	}
	if err := s.DB.InsertDnsLog(dnslog); err != nil {
		// 基础设施错误已在 InsertDnsLog 中记录，这里不重复记录
	}

	s.Logger.Info("开发模式hook：返回默认IP 127.127.127.127",
		zap.String("clientIP", clientIP.String()),
		zap.String("qname", qname),
		zap.String("qtype", qtype),
		zap.Int("traceId", traceId))

	// 发送响应
	if err := s.writePacket(packet, clientAddr, respBytes); err != nil {
		s.Logger.Error("发送默认IP响应到客户端失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.Int("traceId", traceId))
		return true, err
	}

	return true, nil
}

// formatHex 格式化字节为十六进制字符串（参考dig.py样式）
func formatHex(data []byte, maxBytes int) string {
	if len(data) == 0 {
		return "(空)"
	}

	displayLen := maxBytes
	if len(data) < maxBytes {
		displayLen = len(data)
	}

	hexParts := make([]string, displayLen)
	for i := 0; i < displayLen; i++ {
		hexParts[i] = fmt.Sprintf("%02x", data[i])
	}
	hexStr := strings.Join(hexParts, " ")

	if len(data) > maxBytes {
		return fmt.Sprintf("%s ... (总共 %d 字节)", hexStr, len(data))
	}
	return hexStr
}

// printTraceDebug 打印trace模式的调试信息（参考dig.py样式）
func (s *Server) printTraceDebug(label string, message string) {
	s.Logger.Info(fmt.Sprintf("* %s: %s", label, message))
}

// traceDNSRequest 输出DNS请求的详细信息（参考dig.py样式）
func (s *Server) traceDNSRequest(reqBytes []byte, header dnsmessage.Header, question dnsmessage.Question, clientIP net.IP, traceId int) {
	if !s.hasDevMode("trace") {
		return
	}

	s.printTraceDebug("DNS查询消息", fmt.Sprintf("查询 %s %s", question.Name.String(), DnsReqTypeToString(question.Type)))
	fmt.Printf("    原始数据 (%d 字节): %s\n", len(reqBytes), formatHex(reqBytes, 64))
	fmt.Printf("    消息头: ID=%d, QR=%d, Opcode=%d, RD=%d, 问题数=%d\n",
		header.ID, boolToIntDev(header.Response), header.OpCode, boolToIntDev(header.RecursionDesired), len([]dnsmessage.Question{question}))
}

// traceDNSResponse 输出DNS响应的详细信息（参考dig.py样式）
func (s *Server) traceDNSResponse(respBytes []byte, header dnsmessage.Header, clientIP net.IP, traceId int, rtt float64) {
	if !s.hasDevMode("trace") {
		return
	}

	now := time.Now()
	ts := now.Format("2006-01-02 15:04:05.000")

	s.printTraceDebug("DNS响应已接收", fmt.Sprintf("%d 字节", len(respBytes)))
	fmt.Printf("    时间戳: %s\n", ts)
	if rtt > 0 {
		fmt.Printf("    往返时间(RTT): %.2f ms\n", rtt)
	}

	// 从响应数据解析回答数量（DNS头部第5-6字节为ANCount）
	ancount := uint16(0)
	if len(respBytes) >= 6 {
		ancount = uint16(respBytes[4])<<8 | uint16(respBytes[5])
	}

	fmt.Printf("    响应消息头: ID=%d, QR=%d, 响应码=%s, 回答数=%d, AA=%d, RA=%d\n",
		header.ID, boolToIntDev(header.Response), DnsRCodeToString(header.RCode),
		ancount, boolToIntDev(header.Authoritative), boolToIntDev(header.RecursionAvailable))

	fmt.Printf("    原始数据: %s\n", formatHex(respBytes, 64))
}

// traceDNSSend 输出发送DNS响应的详细信息
func (s *Server) traceDNSSend(respBytes []byte, clientAddr net.Addr, traceId int) {
	if !s.hasDevMode("trace") {
		return
	}

	now := time.Now()
	ts := now.Format("2006-01-02 15:04:05.000")

	s.printTraceDebug("发送DNS响应", fmt.Sprintf("%d 字节 -> %s", len(respBytes), clientAddr.String()))
	fmt.Printf("    时间戳: %s\n", ts)
}

// boolToIntDev 将bool转换为int (0或1)，用于dev_mode包
func boolToIntDev(b bool) int {
	if b {
		return 1
	}
	return 0
}
