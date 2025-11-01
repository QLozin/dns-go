package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/dns/dnsmessage"
)

func NewServer(ctx context.Context, opts ...func(*ServerOptions)) *Server {
	option := &ServerOptions{}
	for _, opt := range opts {
		opt(option)
	}
	return &Server{
		ServerOptions: option,
		stopCh:        make(chan struct{}),
		ctx:           ctx,
	}
}
func (s *Server) Stop() {
	close(s.stopCh)
}

func (s *Server) Start() error {
	// 边界层：必须记录所有启动失败的错误
	if err := s.waitBlockerStart(); err != nil {
		s.Logger.Error("等待Blocker启动失败", zap.Error(err))
		s.Stop()
		return err
	}
	if err := s.resolveUpstreamDNS(); err != nil {
		s.Logger.Error("解析上游DNS配置失败", zap.Error(err))
		s.Stop()
		return err
	}
	udpErrCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// 边界层：panic 是系统级错误，必须记录
				s.Logger.Error("UDP服务发生panic", zap.Any("panic", r), zap.Stack("stack"))
			}
		}()
		udpErrCh <- s.serveAtUDP(s.ctx)
	}()
	select {
	case <-s.ctx.Done():
		s.Stop()
		// 边界层：上下文取消是正常关闭，记录为 Info
		s.Logger.Info("Server收到上下文取消信号，正常退出", zap.Error(s.ctx.Err()))
		return s.ctx.Err()
	case err := <-udpErrCh:
		s.Stop()
		// 边界层：UDP服务错误是系统级错误，必须记录
		s.Logger.Error("UDP服务发生错误，Server退出", zap.Error(err))
		return err
	}
}

func (s *Server) resolveUpstreamDNS() error {
	s.upstreamDNS = make([]net.UDPAddr, 0, len(s.ServerConfig.UpstreamDNS))
	for _, upstrm := range s.ServerConfig.UpstreamDNS {
		addr, err := net.ResolveUDPAddr("udp", upstrm)
		if err != nil {
			// 部分失败：记录为 Warn（不是致命错误，可以继续尝试其他上游DNS）
			s.Logger.Warn("解析上游DNS地址失败，跳过",
				zap.String("upstream", upstrm),
				zap.Error(err))
			continue
		}
		s.upstreamDNS = append(s.upstreamDNS, *addr)
	}
	if len(s.upstreamDNS) == 0 {
		// 全部失败：返回错误（调用层会记录为 Error）
		return fmt.Errorf("没有可用的上游DNS，已尝试: %s", strings.Join(s.ServerConfig.UpstreamDNS, ","))
	}
	return nil
}

func (s *Server) waitBlockerStart() error {
	if s.BlockManager == nil {
		return errors.New("BlockManager未初始化")
	}
	timeout := 30 * time.Second
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	s.Logger.Info(fmt.Sprintf("正在等待Blocker载入黑/白名单域名和Geo文件，最长等待 %f 秒", timeout.Seconds()))
	for {
		geoReady := s.BlockManager.GeoReady.Load()
		domainListReady := s.BlockManager.DomainListReady.Load()
		if geoReady && domainListReady {
			s.Logger.Info("Blocker已载入黑/白名单域名和Geo文件，开始启动主服务")
			return nil
		}
		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("等待Blocker载入黑/白名单域名和Geo文件超时")
			}
			s.Logger.Info(fmt.Sprintf("已经等待 %f 秒，Blocker仍未载入黑/白名单域名和Geo文件", time.Since(deadline).Seconds()))
			continue
		case <-s.ctx.Done():
			return fmt.Errorf("上下文取消，Server退出：%w", s.ctx.Err())
		case <-s.stopCh:
			return fmt.Errorf("接收到停止信号，Server退出")
		}
	}
}

func (s *Server) serveAtUDP(ctx context.Context) error {
	// 边界层：网络监听失败是系统级错误，必须记录
	packet, err := net.ListenPacket("udp", s.ServerConfig.UdpPort)
	if err != nil {
		s.Logger.Error("UDP监听失败",
			zap.String("port", s.ServerConfig.UdpPort),
			zap.Error(err))
		return fmt.Errorf("UDP监听失败: %w", err)
	}
	defer packet.Close()

	s.Logger.Info("UDP服务已启动", zap.String("port", s.ServerConfig.UdpPort))
	buffer := make([]byte, 4096)
	for {
		packet.SetReadDeadline(time.Now().Add(5 * time.Second))
		copiedNumber, addr, err := packet.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			s.Logger.Error("UDP读取失败", zap.Error(err))
			return fmt.Errorf("UDP读取失败: %w", err)
		}
		data := make([]byte, copiedNumber)
		copy(data, buffer[:copiedNumber])
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// 边界层：panic 是系统级错误，必须记录
					s.Logger.Error("处理UDP请求时发生panic",
						zap.Any("panic", r),
						zap.Stack("stack"))
				}
			}()
			s.processUDPRequest(ctx, addr, data, packet)
		}()
	}
}

func (s *Server) processUDPRequest(ctx context.Context, clientAddr net.Addr, reqBytes []byte, packet net.PacketConn) error {
	traceId, _ := ctx.Value("traceId").(int)
	blocker := s.BlockManager
	clientUDPAddr, ok := clientAddr.(*net.UDPAddr)
	if !ok {
		// log-options press: 抑制未forward请求的控制台输出
		// 地址类型异常意味着请求不会被处理，所以应该被抑制
		if !s.hasLogOption("press") {
			s.Logger.Debug("客户端地址类型异常",
				zap.Any("clientAddr", clientAddr),
				zap.Int("traceId", traceId))
		}
		return nil
	}
	clientIP := clientUDPAddr.IP
	clientCountry, clientCountryName := s.BlockManager.SearchIPCountry(clientIP)
	var parser dnsmessage.Parser
	header, err := parser.Start(reqBytes)
	if err != nil {
		// log-options press: 抑制未forward请求的控制台输出
		// 解析请求头失败意味着请求不会被forward，所以应该被抑制
		if !s.hasLogOption("press") {
			s.Logger.Debug("客户端请求格式错误（解析请求头失败）",
				zap.Error(err),
				zap.String("clientIP", clientIP.String()),
				zap.Int("traceId", traceId))
		}
		return nil
	}
	ques, err := parser.Question()
	if err != nil {
		s.logQuestionParseError(err, clientIP, traceId, header, reqBytes)
		return nil
	}
	qtype := DnsReqTypeToString(ques.Type)
	qname := ques.Name.String()
	qname = strings.ToLower(qname)
	qname = strings.TrimSuffix(qname, ".")

	// trace模式：输出请求详情
	s.traceDNSRequest(reqBytes, header, ques, clientIP, traceId)
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: header.ID, Response: true, Authoritative: false, RCode: dnsmessage.RCodeNameError},
		Questions: []dnsmessage.Question{ques},
	}
	nxdomain, err := msg.Pack()
	if err != nil {
		// 业务层：打包消息失败是系统错误（代码问题），记录为 Error
		s.Logger.Error("打包NXDOMAIN消息失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.Int("traceId", traceId))
		return nil
	}
	shouldForward := true
	if blocker.isIPAllowed(clientIP) {
		shouldForward = true

	} else if blocker.isIPBlocked(clientIP) || !blocker.isCountryAllowed(clientCountry) {
		shouldForward = false
	} else {
		if blocker.isBlockedDomain(qname) {
			shouldForward = false
		}
	}
	if !shouldForward {
		dnslog := s.buildNXDomainDNSLog(traceId, qname, qtype)
		dnslog.ClientIP = clientIP.String()
		dnslog.GeoCountry = clientCountryName
		if err := s.DB.InsertDnsLog(dnslog); err != nil {
		}
		// log-options press: 抑制未forward请求的控制台输出
		if !s.hasLogOption("press") {
			s.Logger.Debug("DNS请求被阻止（返回NXDOMAIN）",
				zap.String("clientIP", clientIP.String()),
				zap.String("clientCountry", clientCountryName),
				zap.String("qname", qname),
				zap.Int("traceId", traceId))
		}
		if err := s.writePacket(packet, clientAddr, nxdomain); err != nil {
			s.Logger.Error("发送NXDOMAIN响应到客户端失败",
				zap.Error(err),
				zap.String("clientIP", clientIP.String()),
				zap.String("qname", qname),
				zap.Int("traceId", traceId))
			return err
		}
		return nil
	}

	// hook模式：在forward时返回127.127.127.127（仅在shouldForward为true时执行）
	if handled, err := s.handleDevModeHook(header.ID, ques, clientAddr, packet, clientIP, traceId, qname, qtype); handled {
		return err
	}

	resp, rtt, err := s.forwardUDP(ctx, reqBytes)
	if err != nil || len(resp) == 0 {
		errorMsg := ""
		if err != nil {
			errorMsg = err.Error()
		} else {
			errorMsg = "响应为空"
		}
		dnslog := DnsLog{
			Time:        TimeNow(),
			Protocol:    "udp",
			RCode:       "SERVFAIL",
			Blocked:     false,
			RTT:         "0.00ms",
			QName:       qname,
			QType:       qtype,
			MsgId:       traceId,
			ClientIP:    clientIP.String(),
			GeoCountry:  clientCountryName,
			UpstreamDNS: s.upstreamDNS[0].String(),
			Error:       errorMsg,
		}
		if err := s.DB.InsertDnsLog(dnslog); err != nil {
			// 基础设施错误已在 InsertDnsLog 中记录，这里不重复记录
		}
		// 业务事件：转发失败，记录为 Warn（不是系统错误）
		s.Logger.Warn("DNS转发失败",
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.String("upstreamDNS", s.upstreamDNS[0].String()),
			zap.Error(err),
			zap.Int("traceId", traceId))
		if err := s.writePacket(packet, clientAddr, nxdomain); err != nil {
			s.Logger.Error("发送SERVFAIL响应到客户端失败",
				zap.Error(err),
				zap.String("clientIP", clientIP.String()),
				zap.String("qname", qname),
				zap.Int("traceId", traceId))
			return err
		}
		return nil
	}
	dnslog := DnsLog{
		Time:        TimeNow(),
		Protocol:    "udp",
		RCode:       "NOERROR",
		Blocked:     false,
		RTT:         fmt.Sprintf("%.2fms", rtt),
		QName:       qname,
		QType:       qtype,
		MsgId:       traceId,
		ClientIP:    clientIP.String(),
		GeoCountry:  clientCountryName,
		UpstreamDNS: s.upstreamDNS[0].String(),
	}
	if err := s.DB.InsertDnsLog(dnslog); err != nil {
		// 基础设施错误已在 InsertDnsLog 中记录，这里不重复记录
	}
	// 验证响应数据的有效性（至少包含DNS头部）
	if len(resp) < 12 {
		s.Logger.Error("上游DNS响应数据过短，无法解析",
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.Int("responseSize", len(resp)),
			zap.Int("traceId", traceId))
		// 返回SERVFAIL响应
		if err := s.writePacket(packet, clientAddr, nxdomain); err != nil {
			s.Logger.Error("发送SERVFAIL响应失败", zap.Error(err))
		}
		return nil
	}

	// 解析响应头用于trace模式
	var respHeader dnsmessage.Header
	if s.hasDevMode("trace") {
		var respParser dnsmessage.Parser
		h, err := respParser.Start(resp)
		if err == nil {
			respHeader = h
		}
	}

	// trace模式：输出响应详情
	s.traceDNSResponse(resp, respHeader, clientIP, traceId, rtt)

	// 业务事件：成功响应，记录为 Debug（避免日志过多，只记录关键信息）
	s.Logger.Debug("DNS请求成功响应",
		zap.String("clientIP", clientIP.String()),
		zap.String("qname", qname),
		zap.String("qtype", qtype),
		zap.String("rtt", dnslog.RTT),
		zap.Int("traceId", traceId),
		zap.Int("responseSize", len(resp)))

	// trace模式：输出发送详情
	s.traceDNSSend(resp, clientAddr, traceId)

	if err := s.writePacket(packet, clientAddr, resp); err != nil {
		s.Logger.Error("发送DNS响应到客户端失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.String("qtype", qtype),
			zap.Int("responseSize", len(resp)),
			zap.Int("traceId", traceId))
		return err
	}
	s.Logger.Debug("DNS响应已成功发送到客户端",
		zap.String("clientIP", clientIP.String()),
		zap.String("qname", qname),
		zap.Int("traceId", traceId))
	return nil
}

func (s *Server) forwardUDP(ctx context.Context, reqBytes []byte) ([]byte, float64, error) {
	traceId, _ := ctx.Value("traceId").(int)
	// 基础设施层：只包装错误，不记录日志（由调用层决定是否记录）
	if len(s.upstreamDNS) == 0 {
		return nil, 0, fmt.Errorf("%d: 没有可用的上游DNS", traceId)
	}

	upstream := &s.upstreamDNS[0]
	conn, err := net.DialUDP("udp", nil, upstream)
	if err != nil {
		return nil, 0, fmt.Errorf("%d: 连接上游DNS失败 [%s]: %w", traceId, upstream.String(), err)
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	conn.SetDeadline(deadline)
	start := time.Now()

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, 0, fmt.Errorf("%d: 发送DNS请求失败: %w [%s]", traceId, err, upstream.String())
	}

	buffer := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		return nil, 0, fmt.Errorf("%d: 读取DNS响应失败 [%s]: %w", traceId, upstream.String(), err)
	}

	rtt := time.Since(start).Seconds() * 1000
	resp := make([]byte, n)
	copy(resp, buffer[:n])
	return resp, rtt, nil
}

func (s *Server) logQuestionParseError(err error, clientIP net.IP, traceId int, header dnsmessage.Header, reqBytes []byte) {
	// log-options press: 抑制未forward请求的控制台输出
	// 解析错误意味着请求不会被forward，所以应该被抑制
	if s.hasLogOption("press") {
		return
	}

	headerInfo := map[string]interface{}{
		"id":     header.ID,
		"opcode": header.OpCode,
		"rcode":  header.RCode,
	}

	var msg string
	if err == dnsmessage.ErrSectionDone {
		msg = "客户端请求格式错误（请求缺少Question部分）"
	} else {
		msg = "客户端请求格式错误（解析请求问题失败）"
	}

	fields := []zap.Field{
		zap.String("clientIP", clientIP.String()),
		zap.Int("traceId", traceId),
		zap.Int("requestSize", len(reqBytes)),
		// zap.String("requestHex", BytesToHex(reqBytes, 512)),
		zap.Any("dnsHeader", headerInfo),
	}

	if err != dnsmessage.ErrSectionDone {
		fields = append(fields, zap.Error(err))
	}

	s.Logger.Debug(msg, fields...)
}

func (s *Server) buildNXDomainDNSLog(msgId int, qname string, qtype string) DnsLog {
	return DnsLog{
		Time:     TimeNow(),
		Protocol: "udp",
		RCode:    "NXDOMAIN",
		Blocked:  true,
		RTT:      "0.00ms",
		QName:    qname,
		QType:    qtype,
		MsgId:    msgId,
	}
}

// hasLogOption 检查是否启用了指定的日志选项
func (s *Server) hasLogOption(option string) bool {
	for _, opt := range s.LogOptions {
		if opt == option {
			return true
		}
	}
	return false
}

func (s *Server) writePacket(packet net.PacketConn, addr net.Addr, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("尝试发送空响应数据")
	}
	deadline := time.Now().Add(5 * time.Second)
	if err := packet.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("设置写入截止时间失败: %w", err)
	}
	n, err := packet.WriteTo(data, addr)
	if err != nil {
		return fmt.Errorf("写入UDP数据包失败: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("部分写入: 期望%d字节，实际写入%d字节", len(data), n)
	}
	return nil
}
