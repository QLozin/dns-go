package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
)

type IPSet struct {
	Network  []net.IPNet
	SingleIP []net.IP
}

func (i *IPSet) Add(anyip string) error {
	if strings.Contains(anyip, "/") {
		_, net, err := net.ParseCIDR(anyip)
		if err != nil {
			return err
		}
		i.Network = append(i.Network, *net)
	} else {
		ipAddr := net.ParseIP(anyip)
		if ipAddr == nil {
			return fmt.Errorf("无效的IP地址: %s", anyip)
		}
		i.SingleIP = append(i.SingleIP, ipAddr)
	}
	return nil
}

func (i *IPSet) Contains(ip string) bool {
	ipAddr := net.ParseIP(ip)
	for _, net := range i.Network {
		if net.Contains(ipAddr) {
			return true
		}
	}
	for _, singleIP := range i.SingleIP {
		if singleIP.Equal(ipAddr) {
			return true
		}
	}
	return false
}

func NewBlockManager(ctx context.Context, opts ...func(*BlockOptions)) *Blocker {

	option := &BlockOptions{}
	for _, opt := range opts {
		opt(option)
	}
	blocker := &Blocker{
		BlockOptions:   option,
		ctx:            ctx,
		stopCh:         make(chan struct{}),
		domainSet:      make(Set, 10240),
		whiteDomainSet: make(Set, 10240),
		whiteIPSet:     &IPSet{},
		blockIPSet:     &IPSet{},
		localIPSet:     &IPSet{},
	}
	writeLockFirst := os.Getenv("GO_RWMUTEX_WRITESTARVATION")
	if writeLockFirst == "" || writeLockFirst == "0" {
		blocker.Logger.Warn("GO_RWMUTEX_WRITESTARVATION 没有设置或被设置为旧模式（读锁优先），可能产生写锁饥饿")
	}
	blocker.GeoReady.Store(false)
	blocker.DomainListReady.Store(false)
	for _, i := range []string{"127.0.0.0/8", "100.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"} {
		blocker.localIPSet.Add(i)
	}
	for _, i := range blocker.BlockConfig.WhiteIPs {
		blocker.whiteIPSet.Add(i)
	}
	for _, i := range blocker.BlockConfig.BlockIPs {
		blocker.blockIPSet.Add(i)
	}
	return blocker
}

func (b *Blocker) Start() error {
	dir := b.BlockConfig.Dir
	urls := b.BlockConfig.BlockSubscribeURLs
	if dir == "" {
		dir = "./block"
	}
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		b.Logger.Error("创建block目录失败", zap.Error(err))
		return err
	}
	if b.BlockConfig.RefreshHours <= 0 || b.BlockConfig.RefreshHours > 24 {
		b.Logger.Error(fmt.Sprintf("当前 %d 刷新时间间隔无效, 使用默认值6小时", b.BlockConfig.RefreshHours), zap.Int("refresh_hours", b.BlockConfig.RefreshHours))
		b.BlockConfig.RefreshHours = 6
	}
	updateErr := b.UpdateBlockDomain(urls)
	if updateErr != nil {
		return updateErr
	}
	dumpErr := b.DumpToFile()
	if dumpErr != nil {
		return dumpErr
	}
	geoUpdateErr := b.geoip2Update()
	if geoUpdateErr != nil {
		return geoUpdateErr
	}
	// 验证GeoIP2确实已加载到内存
	if b.geoDB.Load() == nil {
		return fmt.Errorf("GeoIP2文件更新完成但未加载到内存")
	}
	b.initWhiteAndBlockDomains()
	go b.scheduleUpdate()
	go b.sheduleUpdateGeo()
	b.GeoReady.Store(true)
	b.DomainListReady.Store(true)
	b.Logger.Info("域名列表和GeoIP2文件更新完成")
	select {
	case <-b.stopCh:
		b.Logger.Info("接收到停止信号，Blocker退出")
		return nil
	case <-b.ctx.Done():
		b.Logger.Info("上下文取消，Blocker退出")
		return b.ctx.Err()
	}
}

func (b *Blocker) Stop() {
	close(b.stopCh)
}

func (b *Blocker) getDomainSet() Set {
	b.mutexes.domainSet.RLock()
	defer b.mutexes.domainSet.RUnlock()
	return b.domainSet
}

func (b *Blocker) initWhiteAndBlockDomains() {
	white := b.BlockConfig.WhiteDomains
	black := b.BlockConfig.BlockDomains
	for _, domain := range white {
		if dm, complied, err := NormailizeDomain(domain); err == nil {
			b.mutexes.whiteDomainSet.Lock()
			b.whiteDomainSet[dm] = complied
			b.mutexes.whiteDomainSet.Unlock()
		} else {
			b.Logger.Error(fmt.Sprintf("白名单域名处理失败: %s", err.Error()))
			continue
		}
	}
	for _, domain := range black {
		if dm, complied, err := NormailizeDomain(domain); err == nil {
			b.mutexes.domainSet.Lock()
			b.domainSet[dm] = complied
			b.mutexes.domainSet.Unlock()
		} else {
			b.Logger.Error(fmt.Sprintf("黑名单域名处理失败: %s", err.Error()))
			continue
		}
	}
	b.Logger.Info("域名列表处理完成")
}

func (b *Blocker) DumpToFile() error {
	dir := b.BlockConfig.Dir
	domainSet := b.getDomainSet()
	if dir == "" {
		dir = "./block"
	}
	outPath := filepath.Join(dir, "domains.txt")
	f, err := os.Create(outPath)
	if err != nil {
		b.Logger.Error("创建domains.txt文件失败", zap.Error(err))
		return err
	}
	defer f.Close()
	writer := bufio.NewWriter(f)
	for d := range domainSet {
		if _, err := writer.WriteString(d + "\n"); err != nil {
			b.Logger.Error(fmt.Sprintf("%s 域名写入domains.txt文件时失败", d), zap.Error(err))
			continue
		}
	}
	if err := writer.Flush(); err != nil {
		b.Logger.Error("写入domains.txt文件失败", zap.Error(err))
		return err
	}
	return nil
}

func (b *Blocker) UpdateBlockDomain(urls []string) error {
	client := NewHttpClient(false)
	for _, url := range urls {
		response, err := client.Get(url)
		if err != nil {
			b.Logger.Error(fmt.Sprintf("获取订阅URL %s 失败", url), zap.Error(err))
			continue
		}
		defer response.Body.Close()
		var respCode = response.StatusCode
		if respCode < 200 || respCode >= 300 {
			b.Logger.Error(fmt.Sprintf("订阅URL %s 响应体解析失败,Code: %d", url, respCode), zap.Int("status_code", respCode))
			continue
		}
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 0, 1024), 64*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) <= 1 {
				continue
			}
			var domain string
			if valid, _ := ValidIP(fields[0]); valid {
				domain = fields[0]
			} else {
				domain = strings.Join(fields[1:], ".")
			}
			if dm, dmExp, err := NormailizeDomain(domain); err == nil {
				b.mutexes.domainSet.Lock()
				b.domainSet[dm] = dmExp
				b.mutexes.domainSet.Unlock()
			} else {
				b.Logger.Error(fmt.Sprintf("域名处理失败: %s", err.Error()))
				continue
			}
		}
		if err := scanner.Err(); err != nil {
			b.Logger.Error(fmt.Sprintf("读取订阅URL %s 并解析域名失败", url), zap.Error(err))
			continue
		}
	}
	return nil
}

func (b *Blocker) scheduleUpdate() {
	urls := b.BlockConfig.BlockSubscribeURLs
	refreshHours := b.BlockConfig.RefreshHours
	ticker := time.NewTicker(time.Duration(refreshHours) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			updateErr := b.UpdateBlockDomain(urls)
			if updateErr != nil {
				b.Logger.Error(fmt.Sprintf("更新域名列表失败: %s", updateErr.Error()))
				continue
			}
			dumpErr := b.DumpToFile()
			if dumpErr != nil {
				b.Logger.Error(fmt.Sprintf("写入域名列表到文件失败: %s", dumpErr.Error()))
				continue
			}
			b.DomainListReady.Store(true)
			b.Logger.Info("域名列表更新完成")
		case <-b.stopCh:
			return
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *Blocker) sheduleUpdateGeo() {
	interval := b.BlockConfig.RefreshHours
	ticker := time.NewTicker(time.Duration(interval) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			updateErr := b.geoip2Update()
			if updateErr != nil {
				b.Logger.Error(fmt.Sprintf("更新GeoIP2文件失败: %s", updateErr.Error()))
				continue
			}
			b.Logger.Info("GeoIP2文件更新完成")
		case <-b.stopCh:
			return
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *Blocker) geoip2Update() error {
	url := b.BlockConfig.GeoIP2URL
	dir := b.BlockConfig.Dir
	geoipPath := filepath.Join(dir, "Country.mmdb")
	var tempPath = geoipPath + ".download"

	if FileExists(geoipPath) {
		fileInfo, err := os.Stat(geoipPath)
		if err == nil {
			modTime := fileInfo.ModTime()
			now := time.Now()
			if now.Sub(modTime) < 15*time.Minute {
				b.Logger.Info("GeoIP2文件存在且未超过15分钟，从本地文件加载",
					zap.String("path", geoipPath),
					zap.Time("mod_time", modTime),
					zap.Duration("age", now.Sub(modTime)))

				data, err := os.ReadFile(geoipPath)
				if err != nil {
					b.Logger.Warn(fmt.Sprintf("读取本地GeoIP2文件失败，将尝试下载: %s", err.Error()))
				} else {
					geoDB, err := geoip2.FromBytes(data)
					if err != nil {
						b.Logger.Warn(fmt.Sprintf("本地GeoIP2文件格式错误，将尝试下载: %s", err.Error()))
					} else {
						b.geoDB.Swap(geoDB)
						b.Logger.Info("GeoIP2文件从本地加载成功", zap.String("path", geoipPath))
						return nil
					}
				}
			} else {
				b.Logger.Info("GeoIP2文件存在但已超过15分钟，将重新下载",
					zap.String("path", geoipPath),
					zap.Time("mod_time", modTime),
					zap.Duration("age", now.Sub(modTime)))
			}
		} else {
			b.Logger.Warn(fmt.Sprintf("获取GeoIP2文件信息失败，将尝试下载: %s", err.Error()))
		}
	} else {
		b.Logger.Info("GeoIP2文件不存在，将下载", zap.String("path", geoipPath))
	}

	resp, err := NewHttpClient(false).Get(url)
	if err != nil {
		b.Logger.Error(fmt.Sprintf("获取 GeoIP2URL %s 失败", url), zap.Error(err))
		return err
	}
	defer resp.Body.Close()
	var respCode = resp.StatusCode
	if respCode < 200 || respCode >= 300 {
		b.Logger.Error(fmt.Sprintf("GeoIP2URL %s 响应体解析失败,Code: %d", url, respCode), zap.Int("status_code", respCode))
		return fmt.Errorf("GeoIP2URL %s 响应体解析失败,Code: %d", url, respCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		b.Logger.Error(fmt.Sprintf("读取GeoIP2URL %s 响应体失败", url), zap.Error(err))
		return err
	}

	// 首先将GeoIP2数据加载到内存（无论文件写入是否成功，都需要加载到内存）
	geoDB, err := geoip2.FromBytes(data)
	if err != nil {
		b.Logger.Error(fmt.Sprintf("GeoIP2文件加载为GeoDB对象失败 %s ", url), zap.Error(err))
		return err
	}
	b.geoDB.Swap(geoDB)
	b.Logger.Info("GeoIP2文件下载完成并加载成功", zap.String("url", url))

	// 然后尝试保存到文件（失败也不影响使用，因为已经加载到内存）
	if err := b.geoip2DumpToFile(tempPath, data); err != nil {
		b.Logger.Warn(fmt.Sprintf("GeoIP2文件写入失败（不影响使用）: %s", err.Error()))
		return nil // 文件写入失败不影响使用，因为已经加载到内存
	}
	err = os.Rename(tempPath, geoipPath)
	if err != nil {
		b.Logger.Warn(fmt.Sprintf("文件下载成功但替换旧文件 %s 失败（不影响使用）: %s", geoipPath, err.Error()))
		return nil // 文件重命名失败不影响使用，因为已经加载到内存
	}
	return nil
}

func (b *Blocker) geoip2DumpToFile(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		b.Logger.Error(fmt.Sprintf("创建 %s 文件失败", path), zap.Error(err))
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		b.Logger.Error(fmt.Sprintf("写入 %s 文件失败", path), zap.Error(err))
		return err
	}
	return nil
}

func (b *Blocker) SearchIPCountry(ip net.IP) (string, string) {
	var code string
	var name string
	if b.localIPSet.Contains(ip.String()) {
		code = "Local"
		name = "本地"
	} else {
		geoDB := b.geoDB.Load()
		if geoDB == nil {
			b.Logger.Error("GeoIP2文件未加载")
			return "", ""
		}
		rec, err := geoDB.Country(ip)
		if err != nil {
			b.Logger.Error("GeoIP2文件搜索IP国家失败", zap.Error(err))
			return "", ""
		}
		code = rec.Country.IsoCode
		name = rec.Country.Names["zh-CN"]
		if code == "" || name == "" {
			b.Logger.Info(fmt.Sprintf("没有找到IP国家信息，查询的IP：%s, 国家代码：%s, 国家名称：%s", ip.String(), code, name))
			return "", ""
		}
	}
	b.Logger.Info(fmt.Sprintf("成功查询IP %s 的国家信息, 国家代码：%s, 国家名称：%s", ip.String(), code, name))
	return code, name
}

func (b *Blocker) isWhiteDomain(domain string) bool {
	domain = SimpleNormalizeDomain(domain)

	b.mutexes.whiteDomainSet.RLock()
	defer b.mutexes.whiteDomainSet.RUnlock()
	fields := strings.Split(domain, ".")
	for i := 0; i < len(fields); i++ {
		subDomain := strings.Join(fields[i:], ".")
		if reg := b.whiteDomainSet[subDomain]; reg != nil {
			if reg.MatchString(domain) {
				return true
			}
		}
	}
	return false

}

func (b *Blocker) isBlockedDomain(domain string) bool {

	domain = SimpleNormalizeDomain(domain)
	b.mutexes.domainSet.RLock()
	defer b.mutexes.domainSet.RUnlock()
	fields := strings.Split(domain, ".")
	for i := 0; i < len(fields); i++ {
		subDomain := strings.Join(fields[i:], ".")
		if reg := b.domainSet[subDomain]; reg != nil {
			if reg.MatchString(domain) {
				return true
			}
		}
	}
	return false
}

func (b *Blocker) isCountryAllowed(countryCode string) bool {
	countryCode = strings.ToLower(countryCode)
	return countryCode == "cn" || countryCode == "local"
}

func (b *Blocker) isIPAllowed(ip net.IP) bool {
	ip_str := ip.String()
	return b.localIPSet.Contains(ip_str) || b.whiteIPSet.Contains(ip_str)
}

func (b *Blocker) isIPBlocked(ip net.IP) bool {
	return b.blockIPSet.Contains(ip.String())
}