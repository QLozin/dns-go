package newdns

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
	if err := this.waitBlockerStart(); err != nil {
		this.Stop()
		return err
	}
	if err := this.resolveUpstreamDNS(); err != nil {
		this.Stop()
		return err
	}
	udpErrCh := make(chan error, 1)

	return nil
}

func (this *Server) resolveUpstreamDNS() error {
	this.upstreamDNS = make([]net.UDPAddr, len(this.ServerConfig.UpstreamDNS))
	for _, upstrm := range this.ServerConfig.UpstreamDNS {
		addr, err := net.ResolveUDPAddr("udp", upstrm)
		if err != nil {
			this.Logger.Error("解析上游DNS失败", zap.Error(err))
			continue
		}
		this.upstreamDNS = append(this.upstreamDNS, *addr)
	}
	if len(this.upstreamDNS) == 0 {
		return fmt.Errorf("没有可用的上游DNS %s", strings.Join(this.ServerConfig.UpstreamDNS, ","))
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
	packet, err := net.ListenPacket("udp", this.ServerConfig.UdpPort)
	if err != nil {
		return err
	}
	defer packet.Close()
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
			return err
		}
		data := make([]byte, copiedNumber)
		copy(data, buffer[:copiedNumber])
		go this.processUDPRequest(ctx, addr, data, packet)
	}

}

func (this *Server) processUDPRequest(ctx context.Context, clientAddr net.Addr, reqBytes []byte, packet net.PacketConn) error {
	msgId := ctx.Value("msgId").(int)
	blocker := this.blockerManager
	clientUDPAddr, ok := clientAddr.(*net.UDPAddr)
	if !ok {
		this.Logger.Error("clientAddr不是*net.UDPAddr类型", zap.Any("clientAddr", clientAddr))
		return fmt.Errorf("clientAddr不是*net.UDPAddr类型")
	}
	clientIP := clientUDPAddr.IP
	clientCountry, clientCountryName := this.blockerManager.SearchIPCountry(clientIP)
	var parser dnsmessage.Parser
	header, err := parser.Start(reqBytes)
	if err != nil {
		this.Logger.Error("解析请求头失败", zap.Error(err))
		return fmt.Errorf("解析请求头失败: %w", err)
	}
	ques, err := parser.Question()
	qtype := DnsReqTypeToString(ques.Type)
	if err != nil {
		this.Logger.Error("解析请求问题失败", zap.Error(err))
		return fmt.Errorf("解析请求问题失败: %w", err)
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
		this.Logger.Error("打包NXDOMAIN失败", zap.Error(err))
		return fmt.Errorf("打包NXDOMAIN失败: %w", err)
	}
	if qname != "" && !blocker.isIPAllowed(clientIP) || !blocker.isCountryAllowed(clientCountry) || (blocker.isBlockedDomain(qname) && !blocker.isWhiteDomain(qname)) {
		dnslog := this.buildNXDomainDNSLog(msgId, qname, qtype)
		dnslog.ClientIP = clientIP.String()
		dnslog.GeoCountry = clientCountryName
		// TODO 插入DNS日志到数据库，暂时先空着
		this.Logger.Info("返回NXDOMAIN", zap.String("clientIP", clientIP.String()), zap.String("clientCountry", clientCountryName))
		return this.writePacket(packet, clientAddr, nxdomain)

	}
	resp, rtt, err := this.forwardUDP(ctx, reqBytes)
	if err != nil {
		this.Logger.Error("转发请求失败", zap.Error(err))
		return fmt.Errorf("转发请求失败: %w", err)
	}
	dnslog := DnsLog{
		Time:        time.Now().Format("YYYY-MM-DD HH:mm:ss"),
		Protocol:    "udp",
		RCode:       "NOERROR",
		Blocked:     false,
		RTT:         fmt.Sprintf("%.2fms", rtt),
		QName:       qname,
		QType:       qtype,
		MsgId:       msgId,
		ClientIP:    clientIP.String(),
		GeoCountry:  clientCountryName,
		UpstreamDNS: this.upstreamDNS[0].String(),
	}
	// TODO 插入DNS日志到数据库，暂时先空着
	this.Logger.Info("返回DNS响应", zap.String("clientIP", clientIP.String()), zap.String("clientCountry", clientCountryName))
	this.Logger.Info("DNS日志", zap.Any("dnslog", dnslog))
	return this.writePacket(packet, clientAddr, resp)
}

func (this *Server) forwardUDP(ctx context.Context, reqBytes []byte) ([]byte, float64, error) {
	conn, err := net.DialUDP("udp", nil, &this.upstreamDNS[0])
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, 0, err
	}
	buffer := make([]byte, 4096)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		return nil, 0, fmt.Errorf("读取响应失败: %w", err)
	}
	rtt := time.Since(start).Seconds() * 1000
	resp := make([]byte, n)
	copy(resp, buffer[:n])
	return resp, rtt, nil

}

func (this *Server) buildNXDomainDNSLog(msgId int, qname string, qtype string) DnsLog {
	return DnsLog{
		Time:     time.Now().Format("YYYY-MM-DD HH:mm:ss"),
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
