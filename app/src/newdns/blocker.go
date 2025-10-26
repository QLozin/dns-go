package newdns

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
	}
	writeLockFirst := os.Getenv("GO_RWMUTEX_WRITESTARVATION")
	if writeLockFirst == "" || writeLockFirst == "0" {
		blocker.Logger.Warn("GO_RWMUTEX_WRITESTARVATION 没有设置或被设置为旧模式（读锁优先），可能产生写锁饥饿")
	}
	return blocker
}

func (this *Blocker) Start() error {
	dir := this.BlockConfig.Dir
	urls := this.BlockConfig.BlockSubscribeURLs
	if dir == "" {
		dir = "./block"
	}
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		this.Logger.Error("创建block目录失败", zap.Error(err))
		return err
	}
	if this.BlockConfig.RefreshHours <= 0 || this.BlockConfig.RefreshHours > 24 {
		this.Logger.Error(fmt.Sprintf("当前 %d 刷新时间间隔无效, 使用默认值6小时", this.BlockConfig.RefreshHours), zap.Int("refresh_hours", this.BlockConfig.RefreshHours))
		this.BlockConfig.RefreshHours = 6
	}
	updateErr := this.UpdateBlockDomain(urls)
	if updateErr != nil {
		return updateErr
	}
	dumpErr := this.DumpToFile()
	if dumpErr != nil {
		return dumpErr
	}
	geoUpdateErr := this.geoip2Update()
	if geoUpdateErr != nil {
		return geoUpdateErr
	}
	this.initWhiteAndBlockDomains()
	go this.scheduleUpdate()
	go this.sheduleUpdateGeo()
	this.GeoReady.Store(true)
	this.DomainListReady.Store(true)
	this.Logger.Info("域名列表和GeoIP2文件更新完成")
	select {
	case <-this.stopCh:
		this.Logger.Info("接收到停止信号，Blocker退出")
		return nil
	case <-this.ctx.Done():
		this.Logger.Info("上下文取消，Blocker退出")
		return this.ctx.Err()
	}
}

func (this *Blocker) getDomainSet() Set {
	this.mutexes.domainSet.RLock()
	defer this.mutexes.domainSet.RUnlock()
	return this.domainSet
}

func (this *Blocker) initWhiteAndBlockDomains() {
	white := this.BlockConfig.WhiteDomains
	black := this.BlockConfig.BlockDomains
	for _, domain := range white {
		if dm, complied, err := NormailizeDomain(domain); err == nil {
			this.mutexes.whiteDomainSet.Lock()
			this.whiteDomainSet[dm] = complied
			this.mutexes.whiteDomainSet.Unlock()
		} else {
			this.Logger.Error(fmt.Sprintf("白名单域名处理失败: %s", err.Error()))
			continue
		}
	}
	for _, domain := range black {
		if dm, complied, err := NormailizeDomain(domain); err == nil {
			this.mutexes.domainSet.Lock()
			this.domainSet[dm] = complied
			this.mutexes.domainSet.Unlock()
		} else {
			this.Logger.Error(fmt.Sprintf("黑名单域名处理失败: %s", err.Error()))
			continue
		}
	}
	this.Logger.Info("域名列表处理完成")
}

func (this *Blocker) DumpToFile() error {
	dir := this.BlockConfig.Dir
	domainSet := this.getDomainSet()
	if dir == "" {
		dir = "./block"
	}
	outPath := filepath.Join(dir, "domains.txt")
	f, err := os.Create(outPath)
	if err != nil {
		this.Logger.Error("创建domains.txt文件失败", zap.Error(err))
		return err
	}
	defer f.Close()
	writer := bufio.NewWriter(f)
	for d := range domainSet {
		if _, err := writer.WriteString(d + "\n"); err != nil {
			this.Logger.Error(fmt.Sprintf("%s 域名写入domains.txt文件时失败", d), zap.Error(err))
			continue
		}
	}
	if err := writer.Flush(); err != nil {
		this.Logger.Error("写入domains.txt文件失败", zap.Error(err))
		return err
	}
	return nil
}

func (this *Blocker) UpdateBlockDomain(urls []string) error {
	client := NewHttpClient(false)
	for _, url := range urls {
		response, err := client.Get(url)
		if err != nil {
			this.Logger.Error(fmt.Sprintf("获取订阅URL %s 失败", url), zap.Error(err))
			continue
		}
		defer response.Body.Close()
		var respCode = response.StatusCode
		if respCode < 200 || respCode >= 300 {
			this.Logger.Error(fmt.Sprintf("订阅URL %s 响应体解析失败,Code: %d", url, respCode), zap.Int("status_code", respCode))
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
				this.mutexes.domainSet.Lock()
				this.domainSet[dm] = dmExp
				this.mutexes.domainSet.Unlock()
			} else {
				this.Logger.Error(fmt.Sprintf("域名处理失败: %s", err.Error()))
				continue
			}
		}
		if err := scanner.Err(); err != nil {
			this.Logger.Error(fmt.Sprintf("读取订阅URL %s 并解析域名失败", url), zap.Error(err))
			continue
		}
	}
	return nil
}

func (this *Blocker) scheduleUpdate() {
	urls := this.BlockConfig.BlockSubscribeURLs
	refreshHours := this.BlockConfig.RefreshHours
	ticker := time.NewTicker(time.Duration(refreshHours) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			updateErr := this.UpdateBlockDomain(urls)
			if updateErr != nil {
				this.Logger.Error(fmt.Sprintf("更新域名列表失败: %s", updateErr.Error()))
				continue
			}
			dumpErr := this.DumpToFile()
			if dumpErr != nil {
				this.Logger.Error(fmt.Sprintf("写入域名列表到文件失败: %s", dumpErr.Error()))
				continue
			}
			this.DomainListReady.Store(true)
			this.Logger.Info("域名列表更新完成")
		case <-this.stopCh:
			return
		case <-this.ctx.Done():
			return
		}
	}
}

func (this *Blocker) sheduleUpdateGeo() {
	interval := this.BlockConfig.RefreshHours
	ticker := time.NewTicker(time.Duration(interval) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			updateErr := this.geoip2Update()
			if updateErr != nil {
				this.Logger.Error(fmt.Sprintf("更新GeoIP2文件失败: %s", updateErr.Error()))
				continue
			}
			this.Logger.Info("GeoIP2文件更新完成")
		case <-this.stopCh:
			return
		case <-this.ctx.Done():
			return
		}
	}
}

func (this *Blocker) geoip2Update() error {
	url := this.BlockConfig.GeoIP2URL
	dir := this.BlockConfig.Dir
	geoipPath := filepath.Join(dir, "Country.mmdb")
	var tempPath = geoipPath + ".download"

	resp, err := NewHttpClient(false).Get(url)
	if err != nil {
		this.Logger.Error(fmt.Sprintf("获取 GeoIP2URL %s 失败", url), zap.Error(err))
		return err
	}
	defer resp.Body.Close()
	var respCode = resp.StatusCode
	if respCode < 200 || respCode >= 300 {
		this.Logger.Error(fmt.Sprintf("GeoIP2URL %s 响应体解析失败,Code: %d", url, respCode), zap.Int("status_code", respCode))
		return fmt.Errorf("GeoIP2URL %s 响应体解析失败,Code: %d", url, respCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err := this.geoip2DumpToFile(geoipPath, data); err == nil {
		err := FileRename(tempPath, geoipPath)
		if err != nil {
			this.Logger.Error(fmt.Sprintf("文件下载成功，替换旧文件 %s 失败", geoipPath), zap.Error(err))
		}
		return err
	}
	geoDB, err := geoip2.FromBytes(data)
	if err != nil {
		this.Logger.Error(fmt.Sprintf("GeoIP2文件加载为GeoDB对象失败 %s ", url), zap.Error(err))
		return err
	}
	this.geoDB.Swap(geoDB)
	this.Logger.Info("GeoIP2文件下载完成并加载成功", zap.String("url", url))
	return nil
}

func (this *Blocker) geoip2DumpToFile(path string, data []byte) error {
	f, err := os.Create(path)
	defer f.Close()
	if err != nil {
		this.Logger.Error(fmt.Sprintf("创建 %s 文件失败", path), zap.Error(err))
		return err
	}
	if _, err := f.Write(data); err != nil {
		this.Logger.Error(fmt.Sprintf("写入 %s 文件失败", path), zap.Error(err))
		return err
	}
	return nil
}

func (this *Blocker) SearchIPCountry(ip net.IP) (string, string) {
	geoDB := this.geoDB.Load()
	if geoDB == nil {
		this.Logger.Error("GeoIP2文件未加载")
		return "", ""
	}
	rec, err := geoDB.Country(ip)
	if err != nil {
		this.Logger.Error("GeoIP2文件搜索IP国家失败", zap.Error(err))
		return "", ""
	}
	var code = rec.Country.IsoCode
	var name = rec.Country.Names["zh-CN"]
	if code == "" || name == "" {
		this.Logger.Info(fmt.Sprintf("没有找到IP国家信息，查询的IP：%s", ip.String(), code, name))
		return "", ""
	}
	this.Logger.Info(fmt.Sprintf("成功查询IP %s 的国家信息, 国家代码：%s, 国家名称：%s", ip.String(), code, name))
	return code, name
}

func (this *Blocker) isWhiteDomain(domain string) bool {
	domain = SimpleNormalizeDomain(domain)

	this.mutexes.whiteDomainSet.RLock()
	defer this.mutexes.whiteDomainSet.RUnlock()
	fields := strings.Split(domain, ".")
	for i := 0; i < len(fields); i++ {
		subDomain := strings.Join(fields[i:], ".")
		if reg := this.whiteDomainSet[subDomain]; reg != nil {
			if reg.MatchString(domain) {
				return true
			}
		}
	}
	return false

}

func (this *Blocker) isBlocedDomain(domain string) bool {

	domain = SimpleNormalizeDomain(domain)
	this.mutexes.domainSet.RLock()
	defer this.mutexes.domainSet.RUnlock()
	fields := strings.Split(domain, ".")
	for i := 0; i < len(fields); i++ {
		subDomain := strings.Join(fields[i:], ".")
		if reg := this.domainSet[subDomain]; reg != nil {
			if reg.MatchString(domain) {
				return true
			}
		}
	}
	return false
}

func (this *Blocker) isIPAllowed(ip net.IP) bool {
	code, _ := this.SearchIPCountry(ip)
	code = strings.ToLower(code)
	if code == "cn" {
		return true
	}
	return false
}
