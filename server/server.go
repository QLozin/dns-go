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
	select {
	case <-s.stopCh:
		// channel已经关闭，无需重复关闭
	default:
		close(s.stopCh)
	}
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
	// 使用 net.ListenUDP 以便更好地控制源IP
	addr, err := net.ResolveUDPAddr("udp", s.ServerConfig.UdpPort)
	if err != nil {
		s.Logger.Error("解析UDP地址失败",
			zap.String("port", s.ServerConfig.UdpPort),
			zap.Error(err))
		return fmt.Errorf("解析UDP地址失败: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		s.Logger.Error("UDP监听失败",
			zap.String("port", s.ServerConfig.UdpPort),
			zap.Error(err))
		return fmt.Errorf("UDP监听失败: %w", err)
	}
	defer conn.Close()

	s.Logger.Info("UDP服务已启动", zap.String("port", s.ServerConfig.UdpPort))
	buffer := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		copiedNumber, clientAddr, err := conn.ReadFromUDP(buffer)
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
			s.processUDPRequest(ctx, clientAddr, data, conn)
		}()
	}
}

func (s *Server) processUDPRequest(ctx context.Context, clientAddr net.Addr, reqBytes []byte, packet net.PacketConn) error {
	// 如果是 UDPConn，直接使用 WriteToUDP，确保从正确的源IP和端口发送
	if udpConn, ok := packet.(*net.UDPConn); ok {
		clientUDPAddr, ok := clientAddr.(*net.UDPAddr)
		if !ok {
			s.Logger.Debug("客户端地址类型异常", zap.Any("clientAddr", clientAddr))
			return nil
		}
		return s.processUDPRequestWithConn(ctx, clientUDPAddr, reqBytes, udpConn)
	}
	// 回退到原始方法
	return s.processUDPRequestOriginal(ctx, clientAddr, reqBytes, packet)
}

// processUDPRequestWithConn 使用 UDPConn 处理请求，确保从正确的源IP和端口发送响应
func (s *Server) processUDPRequestWithConn(ctx context.Context, clientAddr *net.UDPAddr, reqBytes []byte, conn *net.UDPConn) error {
	traceId, _ := ctx.Value("traceId").(int)
	blocker := s.BlockManager
	clientIP := clientAddr.IP
	clientCountry, clientCountryName := s.BlockManager.SearchIPCountry(clientIP)

	// 解析DNS请求
	var parser dnsmessage.Parser
	header, err := parser.Start(reqBytes)
	if err != nil {
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

	// 准备NXDOMAIN响应
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: header.ID, Response: true, Authoritative: false, RCode: dnsmessage.RCodeNameError},
		Questions: []dnsmessage.Question{ques},
	}
	nxdomain, err := msg.Pack()
	if err != nil {
		s.Logger.Error("打包NXDOMAIN消息失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.Int("traceId", traceId))
		return nil
	}

	// 辅助函数：发送阻断响应
	sendBlockResponse := func(reason string) error {
		dnslog := s.buildNXDomainDNSLog(traceId, qname, qtype)
		dnslog.ClientIP = clientIP.String()
		dnslog.GeoCountry = clientCountryName
		if err := s.DB.InsertDnsLog(dnslog); err != nil {
		}
		if s.hasDevMode("trace") && !s.hasLogOption("press") {
			s.Logger.Info(reason,
				zap.String("clientIP", clientIP.String()),
				zap.String("qname", qname),
				zap.String("country", clientCountry))
		}
		if !s.hasLogOption("press") {
			s.Logger.Debug("DNS请求被阻止（返回NXDOMAIN）",
				zap.String("clientIP", clientIP.String()),
				zap.String("clientCountry", clientCountryName),
				zap.String("qname", qname),
				zap.String("reason", reason),
				zap.Int("traceId", traceId))
		}
		// 使用 WriteToUDP 从正确的源IP和端口发送
		deadline := time.Now().Add(5 * time.Second)
		conn.SetWriteDeadline(deadline)
		_, err := conn.WriteToUDP(nxdomain, clientAddr)
		if err != nil {
			s.Logger.Error("发送NXDOMAIN响应到客户端失败",
				zap.Error(err),
				zap.String("clientIP", clientIP.String()),
				zap.String("qname", qname),
				zap.Int("traceId", traceId))
			return err
		}
		return nil
	}

	// IP白名单检查
	if blocker.isIPAllowed(clientIP) {
		if s.hasDevMode("trace") {
			s.Logger.Info("IP在白名单中，允许转发",
				zap.String("clientIP", clientIP.String()),
				zap.String("qname", qname))
		}
		s.traceDNSRequest(reqBytes, header, ques, clientIP, traceId)
	} else {
		// IP黑名单和国家封锁检查
		if blocker.isIPBlocked(clientIP) || !blocker.isCountryAllowed(clientCountry) {
			reason := "IP被阻断或国家不合法，阻止转发"
			if s.hasDevMode("trace") && !s.hasLogOption("press") {
				isBlocked := blocker.isIPBlocked(clientIP)
				countryAllowed := blocker.isCountryAllowed(clientCountry)
				s.Logger.Info(reason,
					zap.String("clientIP", clientIP.String()),
					zap.Bool("isIPBlocked", isBlocked),
					zap.Bool("isCountryAllowed", countryAllowed),
					zap.String("country", clientCountry),
					zap.String("qname", qname))
			}
			return sendBlockResponse(reason)
		}

		// 域名检查
		if blocker.isWhiteDomain(qname) {
			if s.hasDevMode("trace") {
				s.Logger.Info("域名在白名单中，允许转发",
					zap.String("clientIP", clientIP.String()),
					zap.String("qname", qname),
					zap.String("country", clientCountry))
			}
			s.traceDNSRequest(reqBytes, header, ques, clientIP, traceId)
		} else if blocker.isBlockedDomain(qname) {
			if s.hasDevMode("trace") && !s.hasLogOption("press") {
				s.Logger.Info("域名被阻断，阻止转发",
					zap.String("clientIP", clientIP.String()),
					zap.String("qname", qname))
			}
			return sendBlockResponse("域名被阻断，阻止转发")
		} else {
			if s.hasDevMode("trace") {
				s.Logger.Info("普通IP且域名未被阻断，允许转发",
					zap.String("clientIP", clientIP.String()),
					zap.String("qname", qname),
					zap.String("country", clientCountry))
			}
			s.traceDNSRequest(reqBytes, header, ques, clientIP, traceId)
		}
	}

	// hook模式
	if handled, err := s.handleDevModeHook(header.ID, ques, clientAddr, conn, clientIP, traceId, qname, qtype); handled {
		return err
	}

	// 转发请求
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
		}
		s.Logger.Warn("DNS转发失败",
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.String("upstreamDNS", s.upstreamDNS[0].String()),
			zap.Error(err),
			zap.Int("traceId", traceId))
		deadline := time.Now().Add(5 * time.Second)
		conn.SetWriteDeadline(deadline)
		_, err := conn.WriteToUDP(nxdomain, clientAddr)
		if err != nil {
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
	}
	if len(resp) < 12 {
		s.Logger.Error("上游DNS响应数据过短，无法解析",
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.Int("responseSize", len(resp)),
			zap.Int("traceId", traceId))
		deadline := time.Now().Add(5 * time.Second)
		conn.SetWriteDeadline(deadline)
		_, err := conn.WriteToUDP(nxdomain, clientAddr)
		if err != nil {
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

	s.Logger.Debug("DNS请求成功响应",
		zap.String("clientIP", clientIP.String()),
		zap.String("qname", qname),
		zap.String("qtype", qtype),
		zap.String("rtt", dnslog.RTT),
		zap.Int("traceId", traceId),
		zap.Int("responseSize", len(resp)))

	// trace模式：输出准备发送详情
	s.traceDNSSend(resp, clientAddr, traceId)

	// 使用 WriteToUDP 发送响应，确保从正确的源IP和端口发送
	deadline := time.Now().Add(5 * time.Second)
	conn.SetWriteDeadline(deadline)
	_, err = conn.WriteToUDP(resp, clientAddr)
	if err != nil {
		s.traceDNSSendResult(resp, clientAddr, traceId, err)
		s.Logger.Error("发送DNS响应到客户端失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.String("qtype", qtype),
			zap.Int("responseSize", len(resp)),
			zap.Int("traceId", traceId))
		return err
	}

	// trace模式：输出发送成功详情
	s.traceDNSSendResult(resp, clientAddr, traceId, nil)
	s.Logger.Debug("DNS响应已成功发送到客户端",
		zap.String("clientIP", clientIP.String()),
		zap.String("qname", qname),
		zap.Int("traceId", traceId))
	return nil
}

func (s *Server) processUDPRequestOriginal(ctx context.Context, clientAddr net.Addr, reqBytes []byte, packet net.PacketConn) error {
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

	// 解析DNS请求（只解析一次）
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

	// 准备NXDOMAIN响应（用于阻断时返回）
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: header.ID, Response: true, Authoritative: false, RCode: dnsmessage.RCodeNameError},
		Questions: []dnsmessage.Question{ques},
	}
	nxdomain, err := msg.Pack()
	if err != nil {
		s.Logger.Error("打包NXDOMAIN消息失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.Int("traceId", traceId))
		return nil
	}

	// 辅助函数：发送阻断响应并返回
	sendBlockResponse := func(reason string) error {
		dnslog := s.buildNXDomainDNSLog(traceId, qname, qtype)
		dnslog.ClientIP = clientIP.String()
		dnslog.GeoCountry = clientCountryName
		if err := s.DB.InsertDnsLog(dnslog); err != nil {
		}
		// log-options press: 当press启用时，抑制被阻断请求的所有trace日志（只关注被forward的结果）
		if s.hasDevMode("trace") && !s.hasLogOption("press") {
			s.Logger.Info(reason,
				zap.String("clientIP", clientIP.String()),
				zap.String("qname", qname),
				zap.String("country", clientCountry))
		}
		// log-options press: 抑制未forward请求的控制台输出
		if !s.hasLogOption("press") {
			s.Logger.Debug("DNS请求被阻止（返回NXDOMAIN）",
				zap.String("clientIP", clientIP.String()),
				zap.String("clientCountry", clientCountryName),
				zap.String("qname", qname),
				zap.String("reason", reason),
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

	// 1. IP白名单检查：如果在白名单，直接允许，跳过后续检查
	if blocker.isIPAllowed(clientIP) {
		if s.hasDevMode("trace") {
			s.Logger.Info("IP在白名单中，允许转发",
				zap.String("clientIP", clientIP.String()),
				zap.String("qname", qname))
		}
		// trace模式：输出请求详情（IP在白名单，允许打印trace）
		s.traceDNSRequest(reqBytes, header, ques, clientIP, traceId)
		// 继续后续处理（hook模式、forward等）
	} else {
		// 2. IP黑名单和国家封锁检查：如果被封锁，直接阻断
		if blocker.isIPBlocked(clientIP) || !blocker.isCountryAllowed(clientCountry) {
			reason := "IP被阻断或国家不合法，阻止转发"
			// log-options press: 当press启用时，抑制被阻断请求的所有trace日志（只关注被forward的结果）
			if s.hasDevMode("trace") && !s.hasLogOption("press") {
				isBlocked := blocker.isIPBlocked(clientIP)
				countryAllowed := blocker.isCountryAllowed(clientCountry)
				s.Logger.Info(reason,
					zap.String("clientIP", clientIP.String()),
					zap.Bool("isIPBlocked", isBlocked),
					zap.Bool("isCountryAllowed", countryAllowed),
					zap.String("country", clientCountry),
					zap.String("qname", qname))
			}
			return sendBlockResponse(reason)
		}

		// 3. 域名检查：解析qname，判断白名单/黑名单
		if blocker.isWhiteDomain(qname) {
			// 域名在白名单，放行
			if s.hasDevMode("trace") {
				s.Logger.Info("域名在白名单中，允许转发",
					zap.String("clientIP", clientIP.String()),
					zap.String("qname", qname),
					zap.String("country", clientCountry))
			}
			// trace模式：输出请求详情（域名在白名单，允许打印trace）
			s.traceDNSRequest(reqBytes, header, ques, clientIP, traceId)
			// 继续后续处理
		} else if blocker.isBlockedDomain(qname) {
			// 域名在黑名单，阻断
			// log-options press: 当press启用时，抑制被阻断请求的所有trace日志（只关注被forward的结果）
			if s.hasDevMode("trace") && !s.hasLogOption("press") {
				s.Logger.Info("域名被阻断，阻止转发",
					zap.String("clientIP", clientIP.String()),
					zap.String("qname", qname))
			}
			// 域名被阻断，不打印trace
			return sendBlockResponse("域名被阻断，阻止转发")
		} else {
			// 普通IP且域名未被阻断，允许转发
			if s.hasDevMode("trace") {
				s.Logger.Info("普通IP且域名未被阻断，允许转发",
					zap.String("clientIP", clientIP.String()),
					zap.String("qname", qname),
					zap.String("country", clientCountry))
			}
			// trace模式：输出请求详情（域名未被阻断，允许打印trace）
			s.traceDNSRequest(reqBytes, header, ques, clientIP, traceId)
			// 继续后续处理
		}
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

	// trace模式：输出准备发送详情
	s.traceDNSSend(resp, clientAddr, traceId)

	// 发送DNS响应
	if err := s.writePacket(packet, clientAddr, resp); err != nil {
		// trace模式：输出发送失败详情
		s.traceDNSSendResult(resp, clientAddr, traceId, err)
		s.Logger.Error("发送DNS响应到客户端失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.String("qtype", qtype),
			zap.Int("responseSize", len(resp)),
			zap.Int("traceId", traceId))
		return err
	}
	// trace模式：输出发送成功详情
	s.traceDNSSendResult(resp, clientAddr, traceId, nil)
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

// getSourceIPForClient 根据客户端IP查找应该使用的源IP
// 这个方法通过查找与客户端IP在同一子网或可以通过默认路由到达的接口IP
func (s *Server) getSourceIPForClient(clientIP net.IP) (net.IP, error) {
	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %w", err)
	}

	var candidateIPs []net.IP
	var sameSubnetIP net.IP

	// 首先尝试找到与客户端在同一子网的接口
	for _, iface := range interfaces {
		// 跳过环回接口和未启动的接口
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			// 只考虑IPv4地址
			if ip = ip.To4(); ip == nil {
				continue
			}

			// 检查客户端IP是否在同一子网
			if ipNet.Contains(clientIP) {
				sameSubnetIP = ip
				break
			}

			// 收集候选IP
			// 如果客户端是公网IP，优先选择公网IP；如果客户端是私有IP，也考虑私有IP
			if clientIP.IsPrivate() || !ip.IsPrivate() {
				candidateIPs = append(candidateIPs, ip)
			}
		}

		// 如果找到同子网的IP，直接返回
		if sameSubnetIP != nil {
			return sameSubnetIP, nil
		}
	}

	// 如果找不到同子网的接口，从候选中选择
	// 如果客户端是公网IP，优先选择第一个公网IP
	if !clientIP.IsPrivate() {
		for _, ip := range candidateIPs {
			if !ip.IsPrivate() {
				return ip, nil
			}
		}
	}

	// 如果客户端是私有IP或没有公网IP候选，使用第一个候选
	if len(candidateIPs) > 0 {
		return candidateIPs[0], nil
	}

	// 最后尝试：返回第一个非回环的IPv4地址
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			if ip = ip.To4(); ip != nil {
				return ip, nil
			}
		}
	}

	// 如果还是找不到，返回错误
	return nil, fmt.Errorf("无法找到可以路由到客户端 %s 的本地IP", clientIP.String())
}

func (s *Server) writePacket(packet net.PacketConn, addr net.Addr, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("尝试发送空响应数据")
	}

	// 获取客户端UDP地址
	clientUDPAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("无效的客户端地址类型")
	}

	// ⭐ 优先使用原始socket发送（保持源端口为53）
	// 这是最可靠的方法，确保从正确的源IP和端口发送响应
	if udpConn, ok := packet.(*net.UDPConn); ok {
		deadline := time.Now().Add(5 * time.Second)
		if err := udpConn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("设置写入截止时间失败: %w", err)
		}
		_, err := udpConn.WriteToUDP(data, clientUDPAddr)
		if err != nil {
			return fmt.Errorf("写入UDP数据包失败: %w", err)
		}
		return nil
	}

	// 回退到原始方法（如果packet不是UDPConn）
	return s.writePacketFallback(packet, addr, data)
}

// writePacketFallback 回退方法：使用原始的packet.WriteTo
func (s *Server) writePacketFallback(packet net.PacketConn, addr net.Addr, data []byte) error {
	deadline := time.Now().Add(5 * time.Second)
	if err := packet.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("设置写入截止时间失败: %w", err)
	}

	// 记录回退方法的使用（用于调试）
	localAddr := packet.LocalAddr()
	if localUDPAddr, ok := localAddr.(*net.UDPAddr); ok {
		s.Logger.Debug("使用回退方法发送响应",
			zap.String("localAddr", localUDPAddr.String()),
			zap.String("remoteAddr", addr.String()),
			zap.Int("dataSize", len(data)))
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
