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
func (this *Server) Stop() {
	close(this.stopCh)
}

func (this *Server) Start() error {
	// 边界层：必须记录所有启动失败的错误
	if err := this.waitBlockerStart(); err != nil {
		this.Logger.Error("等待Blocker启动失败", zap.Error(err))
		this.Stop()
		return err
	}
	if err := this.resolveUpstreamDNS(); err != nil {
		this.Logger.Error("解析上游DNS配置失败", zap.Error(err))
		this.Stop()
		return err
	}
	udpErrCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// 边界层：panic 是系统级错误，必须记录
				this.Logger.Error("UDP服务发生panic", zap.Any("panic", r), zap.Stack("stack"))
			}
		}()
		udpErrCh <- this.serveAtUDP(this.ctx)
	}()
	select {
	case <-this.ctx.Done():
		this.Stop()
		// 边界层：上下文取消是正常关闭，记录为 Info
		this.Logger.Info("Server收到上下文取消信号，正常退出", zap.Error(this.ctx.Err()))
		return this.ctx.Err()
	case err := <-udpErrCh:
		this.Stop()
		// 边界层：UDP服务错误是系统级错误，必须记录
		this.Logger.Error("UDP服务发生错误，Server退出", zap.Error(err))
		return err
	}
}

func (this *Server) resolveUpstreamDNS() error {
	this.upstreamDNS = make([]net.UDPAddr, 0, len(this.ServerConfig.UpstreamDNS))
	for _, upstrm := range this.ServerConfig.UpstreamDNS {
		addr, err := net.ResolveUDPAddr("udp", upstrm)
		if err != nil {
			// 部分失败：记录为 Warn（不是致命错误，可以继续尝试其他上游DNS）
			this.Logger.Warn("解析上游DNS地址失败，跳过",
				zap.String("upstream", upstrm),
				zap.Error(err))
			continue
		}
		this.upstreamDNS = append(this.upstreamDNS, *addr)
	}
	if len(this.upstreamDNS) == 0 {
		// 全部失败：返回错误（调用层会记录为 Error）
		return fmt.Errorf("没有可用的上游DNS，已尝试: %s", strings.Join(this.ServerConfig.UpstreamDNS, ","))
	}
	return nil
}

func (this *Server) waitBlockerStart() error {
	if this.BlockManager == nil {
		return errors.New("BlockManager未初始化")
	}
	timeout := 30 * time.Second
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	this.Logger.Info(fmt.Sprintf("正在等待Blocker载入黑/白名单域名和Geo文件，最长等待 %s 秒", timeout.Seconds()))
	for {
		geoReady := this.BlockManager.GeoReady.Load()
		domainListReady := this.BlockManager.DomainListReady.Load()
		if geoReady && domainListReady {
			this.Logger.Info("Blocker已载入黑/白名单域名和Geo文件，开始启动主服务")
			return nil
		}
		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("等待Blocker载入黑/白名单域名和Geo文件超时")
			}
			this.Logger.Info(fmt.Sprintf("已经等待 %s 秒，Blocker仍未载入黑/白名单域名和Geo文件", time.Since(deadline).Seconds()))
			continue
		case <-this.ctx.Done():
			return fmt.Errorf("上下文取消，Server退出：%w", this.ctx.Err())
		case <-this.stopCh:
			return fmt.Errorf("接收到停止信号，Server退出")
		}
	}
}

func (this *Server) serveAtUDP(ctx context.Context) error {
	// 边界层：网络监听失败是系统级错误，必须记录
	packet, err := net.ListenPacket("udp", this.ServerConfig.UdpPort)
	if err != nil {
		this.Logger.Error("UDP监听失败",
			zap.String("port", this.ServerConfig.UdpPort),
			zap.Error(err))
		return fmt.Errorf("UDP监听失败: %w", err)
	}
	defer packet.Close()

	this.Logger.Info("UDP服务已启动", zap.String("port", this.ServerConfig.UdpPort))
	buffer := make([]byte, 4096)
	for {
		packet.SetReadDeadline(time.Now().Add(5 * time.Second))
		copiedNumber, addr, err := packet.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超时是正常的，检查上下文
				if ctx.Err() != nil {
					// 上下文取消，正常退出，不记录为错误
					return ctx.Err()
				}
				continue // 超时继续循环
			}
			// 边界层：非超时的网络读取错误，必须记录
			this.Logger.Error("UDP读取失败", zap.Error(err))
			return fmt.Errorf("UDP读取失败: %w", err)
		}
		data := make([]byte, copiedNumber)
		copy(data, buffer[:copiedNumber])
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// 边界层：panic 是系统级错误，必须记录
					this.Logger.Error("处理UDP请求时发生panic",
						zap.Any("panic", r),
						zap.Stack("stack"))
				}
			}()
			this.processUDPRequest(ctx, addr, data, packet)
		}()
	}
}

func (this *Server) processUDPRequest(ctx context.Context, clientAddr net.Addr, reqBytes []byte, packet net.PacketConn) error {
	traceId, _ := ctx.Value("traceId").(int)
	blocker := this.BlockManager
	clientUDPAddr, ok := clientAddr.(*net.UDPAddr)
	if !ok {
		// 业务层：类型错误可能是客户端问题，用 Debug
		this.Logger.Debug("客户端地址类型异常",
			zap.Any("clientAddr", clientAddr),
			zap.Int("traceId", traceId))
		return nil // 不返回错误，避免在调用层记录
	}
	clientIP := clientUDPAddr.IP
	clientCountry, clientCountryName := this.BlockManager.SearchIPCountry(clientIP)
	var parser dnsmessage.Parser
	header, err := parser.Start(reqBytes)
	if err != nil {
		// 业务层：客户端发送了错误格式的请求，用 Debug（不是系统错误）
		this.Logger.Debug("客户端请求格式错误（解析请求头失败）",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.Int("traceId", traceId))
		return nil // 不返回错误，避免在调用层记录
	}
	ques, err := parser.Question()
	qtype := DnsReqTypeToString(ques.Type)
	if err != nil {
		// 业务层：客户端请求格式错误，用 Debug
		this.Logger.Debug("客户端请求格式错误（解析请求问题失败）",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.Int("traceId", traceId))
		return nil // 不返回错误，避免在调用层记录
	}
	qname := ques.Name.String()
	qname = strings.ToLower(qname)
	qname = strings.TrimSuffix(qname, ".")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: header.ID, Response: true, Authoritative: false, RCode: dnsmessage.RCodeNameError},
		Questions: []dnsmessage.Question{ques},
	}
	nxdomain, err := msg.Pack()
	if err != nil {
		// 业务层：打包消息失败是系统错误（代码问题），记录为 Error
		this.Logger.Error("打包NXDOMAIN消息失败",
			zap.Error(err),
			zap.String("clientIP", clientIP.String()),
			zap.Int("traceId", traceId))
		return nil // 错误已记录，不返回避免重复
	}
	if (qname != "" && !blocker.isIPAllowed(clientIP)) || !blocker.isCountryAllowed(clientCountry) || (blocker.isBlockedDomain(qname) && !blocker.isWhiteDomain(qname)) {
		// 业务层：这是业务事件（阻止请求），记录为 Info
		dnslog := this.buildNXDomainDNSLog(traceId, qname, qtype)
		dnslog.ClientIP = clientIP.String()
		dnslog.GeoCountry = clientCountryName
		if err := this.DB.InsertDnsLog(dnslog); err != nil {
			// 基础设施错误已在 InsertDnsLog 中记录，这里不重复记录
		}
		// 业务事件：成功阻止请求
		this.Logger.Debug("DNS请求被阻止（返回NXDOMAIN）",
			zap.String("clientIP", clientIP.String()),
			zap.String("clientCountry", clientCountryName),
			zap.String("qname", qname),
			zap.Int("traceId", traceId))
		return this.writePacket(packet, clientAddr, nxdomain)
	}
	resp, rtt, err := this.forwardUDP(ctx, reqBytes)
	if err != nil || len(resp) == 0 {
		// 业务层：转发失败是业务事件，记录为 Warn（已入库）
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
			UpstreamDNS: this.upstreamDNS[0].String(),
			Error:       errorMsg,
		}
		if err := this.DB.InsertDnsLog(dnslog); err != nil {
			// 基础设施错误已在 InsertDnsLog 中记录，这里不重复记录
		}
		// 业务事件：转发失败，记录为 Warn（不是系统错误）
		this.Logger.Warn("DNS转发失败",
			zap.String("clientIP", clientIP.String()),
			zap.String("qname", qname),
			zap.String("upstreamDNS", this.upstreamDNS[0].String()),
			zap.Error(err),
			zap.Int("traceId", traceId))
		return this.writePacket(packet, clientAddr, nxdomain)
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
		UpstreamDNS: this.upstreamDNS[0].String(),
	}
	if err := this.DB.InsertDnsLog(dnslog); err != nil {
		// 基础设施错误已在 InsertDnsLog 中记录，这里不重复记录
	}
	// 业务事件：成功响应，记录为 Debug（避免日志过多，只记录关键信息）
	this.Logger.Debug("DNS请求成功响应",
		zap.String("clientIP", clientIP.String()),
		zap.String("qname", qname),
		zap.String("qtype", qtype),
		zap.String("rtt", dnslog.RTT),
		zap.Int("traceId", traceId))
	return this.writePacket(packet, clientAddr, resp)
}

func (this *Server) forwardUDP(ctx context.Context, reqBytes []byte) ([]byte, float64, error) {
	// 基础设施层：只包装错误，不记录日志（由调用层决定是否记录）
	if len(this.upstreamDNS) == 0 {
		return nil, 0, fmt.Errorf("没有可用的上游DNS")
	}

	upstream := &this.upstreamDNS[0]
	conn, err := net.DialUDP("udp", nil, upstream)
	if err != nil {
		return nil, 0, fmt.Errorf("连接上游DNS失败 [%s]: %w", upstream.String(), err)
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	conn.SetDeadline(deadline)
	start := time.Now()

	if _, err := conn.Write(reqBytes); err != nil {
		return nil, 0, fmt.Errorf("发送DNS请求失败 [%s]: %w", upstream.String(), err)
	}

	buffer := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		return nil, 0, fmt.Errorf("读取DNS响应失败 [%s]: %w", upstream.String(), err)
	}

	rtt := time.Since(start).Seconds() * 1000
	resp := make([]byte, n)
	copy(resp, buffer[:n])
	return resp, rtt, nil
}

func (this *Server) buildNXDomainDNSLog(msgId int, qname string, qtype string) DnsLog {
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

func (this *Server) writePacket(packet net.PacketConn, addr net.Addr, data []byte) error {
	_ = packet.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := packet.WriteTo(data, addr)
	return err
}
