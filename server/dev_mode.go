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

// traceDNSRequest 输出DNS请求的详细信息（参考curl -vv和dig.py样式）
func (s *Server) traceDNSRequest(reqBytes []byte, header dnsmessage.Header, question dnsmessage.Question, clientIP net.IP, traceId int) {
	if !s.hasDevMode("trace") {
		return
	}

	now := time.Now()
	ts := now.Format("2006-01-02 15:04:05.000")

	fmt.Printf("\n")
	s.printTraceDebug("=== DNS查询请求 ===", "")
	fmt.Printf("    客户端IP: %s\n", clientIP.String())
	fmt.Printf("    时间戳: %s\n", ts)
	fmt.Printf("    跟踪ID: %d\n", traceId)

	s.printTraceDebug("DNS查询消息", fmt.Sprintf("查询 %s %s", question.Name.String(), DnsReqTypeToString(question.Type)))
	fmt.Printf("    原始数据 (%d 字节): %s\n", len(reqBytes), formatHex(reqBytes, 64))

	// 详细的DNS消息头信息
	// 问题数（QDCOUNT）：DNS查询中Question部分的数量，通常为1（一次查询一个域名的某类记录）
	fmt.Printf("    DNS消息头详情:\n")
	fmt.Printf("      ID (事务ID): %d (0x%04x)\n", header.ID, header.ID)
	fmt.Printf("      标志位:\n")
	fmt.Printf("        QR (查询/响应): %d (%s)\n", boolToIntDev(header.Response), map[bool]string{false: "查询", true: "响应"}[header.Response])
	fmt.Printf("        Opcode (操作码): %d (%s)\n", header.OpCode, getOpcodeString(header.OpCode))
	fmt.Printf("        AA (权威应答): %d\n", boolToIntDev(header.Authoritative))
	fmt.Printf("        TC (截断标志): %d\n", boolToIntDev(header.Truncated))
	fmt.Printf("        RD (递归期望): %d\n", boolToIntDev(header.RecursionDesired))
	fmt.Printf("        RA (递归可用): %d\n", boolToIntDev(header.RecursionAvailable))
	fmt.Printf("        RCode (响应码): %d (%s)\n", int(header.RCode), DnsRCodeToString(header.RCode))
	fmt.Printf("      计数:\n")
	fmt.Printf("        问题数 (QDCOUNT): %d (DNS查询中Question部分的数量，通常为1，表示一次查询一个域名)\n", len([]dnsmessage.Question{question}))
	fmt.Printf("        回答数 (ANCOUNT): 0 (响应中的Answer记录数)\n")
	fmt.Printf("        授权数 (NSCOUNT): 0 (响应中的Authority记录数)\n")
	fmt.Printf("        额外数 (ARCOUNT): 0 (响应中的Additional记录数)\n")
	fmt.Printf("    问题详情:\n")
	fmt.Printf("      域名: %s\n", question.Name.String())
	fmt.Printf("      类型: %s (%d)\n", DnsReqTypeToString(question.Type), uint16(question.Type))
	fmt.Printf("      类别: IN (%d)\n", uint16(question.Class))
}

// getOpcodeString 获取操作码的字符串表示
func getOpcodeString(opcode dnsmessage.OpCode) string {
	switch int(opcode) {
	case 0:
		return "标准查询 (QUERY)"
	case 1:
		return "反向查询 (IQUERY)"
	case 2:
		return "状态查询 (STATUS)"
	case 3:
		return "通知 (NOTIFY)"
	case 4:
		return "更新 (UPDATE)"
	default:
		return fmt.Sprintf("未知(%d)", int(opcode))
	}
}

// traceDNSResponse 输出DNS响应的详细信息（参考curl -vv和dig.py样式）
func (s *Server) traceDNSResponse(respBytes []byte, header dnsmessage.Header, clientIP net.IP, traceId int, rtt float64) {
	if !s.hasDevMode("trace") {
		return
	}

	now := time.Now()
	ts := now.Format("2006-01-02 15:04:05.000")

	fmt.Printf("\n")
	s.printTraceDebug("=== DNS响应消息 ===", "")
	fmt.Printf("    客户端IP: %s\n", clientIP.String())
	s.printTraceDebug("DNS响应已接收", fmt.Sprintf("%d 字节", len(respBytes)))
	fmt.Printf("    时间戳: %s\n", ts)
	if rtt > 0 {
		fmt.Printf("    往返时间(RTT): %.2f ms\n", rtt)
	}

	// 从响应数据解析计数（DNS头部字节4-11）
	qdcount := uint16(0)
	ancount := uint16(0)
	nscount := uint16(0)
	arcount := uint16(0)
	if len(respBytes) >= 12 {
		qdcount = uint16(respBytes[4])<<8 | uint16(respBytes[5])
		ancount = uint16(respBytes[6])<<8 | uint16(respBytes[7])
		nscount = uint16(respBytes[8])<<8 | uint16(respBytes[9])
		arcount = uint16(respBytes[10])<<8 | uint16(respBytes[11])
	}

	fmt.Printf("    DNS消息头详情:\n")
	fmt.Printf("      ID (事务ID): %d (0x%04x)\n", header.ID, header.ID)
	fmt.Printf("      标志位:\n")
	fmt.Printf("        QR (查询/响应): %d (%s)\n", boolToIntDev(header.Response), map[bool]string{false: "查询", true: "响应"}[header.Response])
	fmt.Printf("        Opcode (操作码): %d (%s)\n", header.OpCode, getOpcodeString(header.OpCode))
	fmt.Printf("        AA (权威应答): %d\n", boolToIntDev(header.Authoritative))
	fmt.Printf("        TC (截断标志): %d\n", boolToIntDev(header.Truncated))
	fmt.Printf("        RD (递归期望): %d\n", boolToIntDev(header.RecursionDesired))
	fmt.Printf("        RA (递归可用): %d\n", boolToIntDev(header.RecursionAvailable))
	fmt.Printf("        RCode (响应码): %d (%s)\n", int(header.RCode), DnsRCodeToString(header.RCode))
	fmt.Printf("      计数:\n")
	fmt.Printf("        问题数 (QDCOUNT): %d\n", qdcount)
	fmt.Printf("        回答数 (ANCOUNT): %d\n", ancount)
	fmt.Printf("        授权数 (NSCOUNT): %d\n", nscount)
	fmt.Printf("        额外数 (ARCOUNT): %d\n", arcount)

	// 解析并显示响应内容
	var parser dnsmessage.Parser
	if _, err := parser.Start(respBytes); err == nil {
		// 跳过Questions部分
		for {
			_, err := parser.Question()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				break
			}
		}

		// 解析Answers
		if ancount > 0 {
			fmt.Printf("    回答记录 (Answer, %d 条):\n", ancount)
			answerIdx := 0
			for {
				answer, err := parser.Answer()
				if err == dnsmessage.ErrSectionDone {
					break
				}
				if err != nil {
					fmt.Printf("      解析错误: %v\n", err)
					break
				}
				answerIdx++
				fmt.Printf("      [%d] %s\n", answerIdx, formatDNSResource(answer))
			}
		}

		// 解析Authority
		if nscount > 0 {
			fmt.Printf("    授权记录 (Authority, %d 条):\n", nscount)
			nsIdx := 0
			for {
				ns, err := parser.Authority()
				if err == dnsmessage.ErrSectionDone {
					break
				}
				if err != nil {
					fmt.Printf("      解析错误: %v\n", err)
					break
				}
				nsIdx++
				fmt.Printf("      [%d] %s\n", nsIdx, formatDNSResource(ns))
			}
		}

		// 解析Additional
		if arcount > 0 {
			fmt.Printf("    额外记录 (Additional, %d 条):\n", arcount)
			addIdx := 0
			for {
				add, err := parser.Additional()
				if err == dnsmessage.ErrSectionDone {
					break
				}
				if err != nil {
					fmt.Printf("      解析错误: %v\n", err)
					break
				}
				addIdx++
				fmt.Printf("      [%d] %s\n", addIdx, formatDNSResource(add))
			}
		}
	}

	fmt.Printf("    原始数据: %s\n", formatHex(respBytes, 64))
}

// formatDNSResource 格式化DNS资源记录
func formatDNSResource(resource dnsmessage.Resource) string {
	name := resource.Header.Name.String()
	ttl := resource.Header.TTL
	class := "IN"
	rtype := DnsReqTypeToString(resource.Header.Type)

	var data string
	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		data = fmt.Sprintf("%d.%d.%d.%d", body.A[0], body.A[1], body.A[2], body.A[3])
	case *dnsmessage.AAAAResource:
		data = net.IP(body.AAAA[:]).String()
	case *dnsmessage.CNAMEResource:
		data = body.CNAME.String()
	case *dnsmessage.MXResource:
		data = fmt.Sprintf("%d %s", body.Pref, body.MX.String())
	case *dnsmessage.NSResource:
		data = body.NS.String()
	case *dnsmessage.TXTResource:
		data = strings.Join(body.TXT, " ")
	case *dnsmessage.SRVResource:
		data = fmt.Sprintf("%d %d %d %s", body.Priority, body.Weight, body.Port, body.Target.String())
	default:
		data = fmt.Sprintf("%v", resource.Body)
	}

	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", name, ttl, class, rtype, data)
}

// traceDNSSend 输出发送DNS响应的详细信息（发送前）
func (s *Server) traceDNSSend(respBytes []byte, clientAddr net.Addr, traceId int) {
	if !s.hasDevMode("trace") {
		return
	}

	now := time.Now()
	ts := now.Format("2006-01-02 15:04:05.000")

	s.printTraceDebug("准备发送DNS响应", fmt.Sprintf("%d 字节 -> %s", len(respBytes), clientAddr.String()))
	fmt.Printf("    时间戳: %s\n", ts)
	fmt.Printf("    目标地址: %s\n", clientAddr.String())
}

// traceDNSSendResult 输出DNS响应发送结果（发送后）
func (s *Server) traceDNSSendResult(respBytes []byte, clientAddr net.Addr, traceId int, err error) {
	if !s.hasDevMode("trace") {
		return
	}

	now := time.Now()
	ts := now.Format("2006-01-02 15:04:05.000")

	fmt.Printf("\n")
	s.printTraceDebug("DNS响应发送结果", "")
	fmt.Printf("    客户端地址: %s\n", clientAddr.String())
	fmt.Printf("    响应大小: %d 字节\n", len(respBytes))
	fmt.Printf("    时间戳: %s\n", ts)
	if err != nil {
		fmt.Printf("    状态: ❌ 发送失败\n")
		fmt.Printf("    错误信息: %s\n", err.Error())
		s.Logger.Error("DNS响应发送失败（trace模式）",
			zap.String("clientAddr", clientAddr.String()),
			zap.Int("responseSize", len(respBytes)),
			zap.Int("traceId", traceId),
			zap.Error(err))
	} else {
		fmt.Printf("    状态: ✅ 发送成功\n")
		fmt.Printf("    已发送字节数: %d 字节\n", len(respBytes))
		s.Logger.Debug("DNS响应发送成功（trace模式）",
			zap.String("clientAddr", clientAddr.String()),
			zap.Int("responseSize", len(respBytes)),
			zap.Int("traceId", traceId))
	}
}

// boolToIntDev 将bool转换为int (0或1)，用于dev_mode包
func boolToIntDev(b bool) int {
	if b {
		return 1
	}
	return 0
}
