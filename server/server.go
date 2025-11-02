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
				s.Logger.Error("UDP服务发生panic", zap.Any("panic", r), zap.Stack("stack"))
			}
		}()
		udpErrCh <- s.serveAtUDP(s.ctx)
	}()
	select {
	case <-s.ctx.Done():
		s.Stop()
		s.Logger.Info("Server收到上下文取消信号，正常退出", zap.Error(s.ctx.Err()))
		return s.ctx.Err()
	case err := <-udpErrCh:
		s.Stop()
		s.Logger.Error("UDP服务发生错误，Server退出", zap.Error(err))
		return err
	}
}

func (s *Server) resolveUpstreamDNS() error {
	s.upstreamDNS = make([]net.UDPAddr, 0, len(s.ServerConfig.UpstreamDNS))
	for _, upstrm := range s.ServerConfig.UpstreamDNS {
		addr, err := net.ResolveUDPAddr("udp", upstrm)
		if err != nil {
			s.Logger.Warn("解析上游DNS地址失败，跳过",
				zap.String("upstream", upstrm),
				zap.Error(err))
			continue
		}
		s.upstreamDNS = append(s.upstreamDNS, *addr)
	}
	if len(s.upstreamDNS) == 0 {
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
		s.Logger.Debug("客户端地址类型异常",
			zap.Any("clientAddr", clientAddr),
			zap.Int("traceId", traceId))
		return nil
	}
	clientIP := clientUDPAddr.IP
	clientCountry, clientCountryName := s.BlockManager.SearchIPCountry(clientIP)

	var parser dnsmessage.Parser
	header, err := parser.Start(reqBytes)
	if err != nil {
		s.Logger.Debug("客户端请求格式错误（解析请求头失败）",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.Int("traceId", traceId))
		return nil
	}

	sendBlockResponseWithoutQname := func(reason string) error {
		var questionParser dnsmessage.Parser
		_, qerr := questionParser.Start(reqBytes)
		var nxdomain []byte
		var qname, qtype string

		if qerr == nil {
			ques, qerr := questionParser.Question()
			if qerr == nil {
				qtype = DnsReqTypeToString(ques.Type)
				qname = ques.Name.String()
				qname = strings.ToLower(qname)
				qname = strings.TrimSuffix(qname, ".")

				msg := dnsmessage.Message{
					Header:    dnsmessage.Header{ID: header.ID, Response: true, Authoritative: false, RCode: dnsmessage.RCodeNameError},
					Questions: []dnsmessage.Question{ques},
				}
				var packErr error
				nxdomain, packErr = msg.Pack()
				if packErr != nil {
					s.Logger.Error("打包NXDOMAIN消息失败",
						zap.Error(packErr),
						zap.String("clientIP", clientIP.String()),
						zap.Int("traceId", traceId))
					return nil
				}
			}
		}

		if qname == "" {
			qtype = ""
			msg := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 header.ID,
					Response:           true,
					Authoritative:      false,
					RCode:              dnsmessage.RCodeFormatError,
					RecursionDesired:   header.RecursionDesired,
					RecursionAvailable: true,
				},
				Questions: []dnsmessage.Question{},
			}
			var packErr error
			nxdomain, packErr = msg.Pack()
			if packErr != nil {
				s.Logger.Error("打包FORMERR消息失败",
					zap.Error(packErr),
					zap.String("clientIP", clientIP.String()),
					zap.Int("traceId", traceId))
				return nil
			}
		}

		var dnslog DnsLog
		if qname != "" {
			dnslog = s.buildNXDomainDNSLog(traceId, qname, qtype)
		} else {
			dnslog = DnsLog{
				Time:     TimeNow(),
				Protocol: "udp",
				RCode:    "FORMERR",
				Blocked:  true,
				RTT:      "0.00ms",
				QName:    "",
				QType:    "",
				MsgId:    traceId,
			}
		}
		dnslog.ClientIP = clientIP.String()
		dnslog.GeoCountry = clientCountryName
		if err := s.DB.InsertDnsLog(dnslog); err != nil {
		}

		logFields := []zap.Field{
			zap.String("clientIP", clientIP.String()),
			zap.String("clientCountry", clientCountryName),
			zap.String("reason", reason),
			zap.Int("traceId", traceId),
		}
		if qname != "" {
			logFields = append(logFields, zap.String("qname", qname))
		}

		s.Logger.Debug("DNS请求被阻止（返回阻断响应）", logFields...)
		if err := s.writePacket(packet, clientAddr, nxdomain); err != nil {
			s.Logger.Error("发送阻断响应到客户端失败",
				zap.Error(err),
				zap.String("clientIP", clientIP.String()),
				zap.Int("traceId", traceId))
			return err
		}
		return nil
	}

	if blocker.isIPAllowed(clientIP) {
	} else {
		if blocker.isIPBlocked(clientIP) {
			return sendBlockResponseWithoutQname("IP被阻断，阻止转发")
		}

		if !blocker.isCountryAllowed(clientCountry) {
			return sendBlockResponseWithoutQname("国家/城市被阻断，阻止转发")
		}
	}

	ques, err := parser.Question()
	if err != nil {
		s.logQuestionParseError(err, clientIP, traceId, header, reqBytes)
		return sendBlockResponseWithoutQname("请求格式错误")
	}

	qtype := DnsReqTypeToString(ques.Type)
	qname := ques.Name.String()
	qname = strings.ToLower(qname)
	qname = strings.TrimSuffix(qname, ".")

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

	sendDomainBlockResponse := func(reason string) error {
		dnslog := s.buildNXDomainDNSLog(traceId, qname, qtype)
		dnslog.ClientIP = clientIP.String()
		dnslog.GeoCountry = clientCountryName
		if err := s.DB.InsertDnsLog(dnslog); err != nil {
		}
		s.Logger.Debug("DNS请求被阻止（返回NXDOMAIN）",
			zap.String("clientIP", clientIP.String()),
			zap.String("clientCountry", clientCountryName),
			zap.String("qname", qname),
			zap.String("reason", reason),
			zap.Int("traceId", traceId))
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

	if blocker.isWhiteDomain(qname) {
	} else if blocker.isBlockedDomain(qname) {
		return sendDomainBlockResponse("域名被阻断，阻止转发")
	}

	resp, rtt, err := s.forwardUDP(ctx, reqBytes)
	if err != nil || len(resp) == 0 {
		return s.handleForwardError(err, qname, qtype, clientIP, clientCountryName, traceId, packet, clientAddr, nxdomain)
	}

	if err := s.handleForwardSuccess(resp, rtt, qname, qtype, clientIP, clientCountryName, traceId, packet, clientAddr); err != nil {
		return err
	}
	return nil
}

func (s *Server) forwardUDP(ctx context.Context, reqBytes []byte) ([]byte, float64, error) {
	traceId, _ := ctx.Value("traceId").(int)
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

func (s *Server) handleForwardError(err error, qname, qtype string, clientIP net.IP, clientCountryName string, traceId int, packet net.PacketConn, clientAddr net.Addr, nxdomain []byte) error {
	errorMsg := "响应为空"
	if err != nil {
		errorMsg = err.Error()
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
	_ = s.DB.InsertDnsLog(dnslog)

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

func (s *Server) handleForwardSuccess(resp []byte, rtt float64, qname, qtype string, clientIP net.IP, clientCountryName string, traceId int, packet net.PacketConn, clientAddr net.Addr) error {
	if len(resp) < 12 {
		s.Logger.Error("上游DNS响应数据过短，无法解析",
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.Int("responseSize", len(resp)),
			zap.Int("traceId", traceId))
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
	_ = s.DB.InsertDnsLog(dnslog)

	s.Logger.Debug("DNS请求成功响应",
		zap.String("clientIP", clientIP.String()),
		zap.String("qname", qname),
		zap.String("qtype", qtype),
		zap.String("rtt", dnslog.RTT),
		zap.Int("traceId", traceId),
		zap.Int("responseSize", len(resp)))

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
	return nil
}

func (s *Server) logQuestionParseError(err error, clientIP net.IP, traceId int, header dnsmessage.Header, reqBytes []byte) {
	headerInfo := map[string]interface{}{
		"id":     header.ID,
		"opcode": header.OpCode,
		"rcode":  header.RCode,
	}

	var msg string
	if err == dnsmessage.ErrSectionDone {
		msg = "客户端请求格式错误（DNS请求缺少Question部分失败）"
	} else {
		msg = "客户端请求格式错误（DNS请求解析失败）"
	}

	fields := []zap.Field{
		zap.String("clientIP", clientIP.String()),
		zap.Int("traceId", traceId),
		zap.Int("requestSize", len(reqBytes)),
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
