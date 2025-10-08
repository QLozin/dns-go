package dns

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	geoip2 "github.com/oschwald/geoip2-golang"
	"golang.org/x/net/dns/dnsmessage"
)

type BlockManager struct {
	mu                sync.RWMutex
	blacklistExactSet map[string]struct{}
	whitelistRegexps  []*regexp.Regexp
	sourceURLs        []string
	whitelistPatterns []string
	dataDir           string
	geoipURL          string
	geoDBReady        bool
	geoDBPath         string
	geoDB             *geoip2.Reader
}

func NewBlockManager(envPath string) *BlockManager {
	cfg, _ := LoadConfig(envPath)
	var urls []string
	var whitelist []string
	var geoURL string
	if cfg != nil {
		urls = append(urls, cfg.Block.URLs...)
		whitelist = append(whitelist, cfg.Block.WhiteList...)
		geoURL = cfg.Block.GeoIP2URL
	}
	bm := &BlockManager{
		blacklistExactSet: make(map[string]struct{}),
		whitelistRegexps:  nil,
		sourceURLs:        urls,
		whitelistPatterns: whitelist,
		dataDir:           filepath.Join("block"),
		geoipURL:          geoURL,
		geoDBPath:         filepath.Join("block", "Country.mmdb"),
	}
	_ = os.MkdirAll(bm.dataDir, 0o755)
	bm.compileWhitelist()
	return bm
}

func (b *BlockManager) compileWhitelist() {
	b.mu.Lock()
	defer b.mu.Unlock()
	// 清空切片
	b.whitelistRegexps = b.whitelistRegexps[:0]
	for _, pat := range b.whitelistPatterns {
		rx := pat
		if !strings.HasPrefix(rx, "^") && !strings.HasSuffix(rx, "$") {
			rx = regexp.QuoteMeta(rx)
			rx = strings.ReplaceAll(rx, "\\*", ".*")
			rx = "^" + rx + "$"
		}
		if compiled, err := regexp.Compile(rx); err == nil {
			b.whitelistRegexps = append(b.whitelistRegexps, compiled)
		}
	}
}

func (b *BlockManager) IsWhitelisted(domain string) bool {
	d := normalizeDomain(domain)
	b.mu.RLock()
	regs := b.whitelistRegexps
	b.mu.RUnlock()
	for _, r := range regs {
		if r.MatchString(d) {
			return true
		}
	}
	return false
}

func (b *BlockManager) IsBlocked(domain string) bool {
	d := normalizeDomain(domain)
	b.mu.RLock()
	set := b.blacklistExactSet
	b.mu.RUnlock()
	if d == "" {
		return false
	}
	labels := strings.Split(d, ".")
	for i := 0; i < len(labels); i++ {
		cand := strings.Join(labels[i:], ".")
		if _, ok := set[cand]; ok {
			return true
		}
	}
	return false
}

func (b *BlockManager) UpdateNow() {
	if len(b.sourceURLs) == 0 {
		return
	}
	tmpSet := make(map[string]struct{}, 1_000_000)
	for _, u := range b.sourceURLs {
		domains, err := downloadAndExtractDomains(u)
		if err != nil {
			continue
		}
		fileBase := safeFilenameFromURL(u)
		outPath := filepath.Join(b.dataDir, fileBase+".domains")
		_ = writeLines(outPath, domains)
		for _, d := range domains {
			if d == "" {
				continue
			}
			tmpSet[d] = struct{}{}
		}
	}
	b.mu.Lock()
	b.blacklistExactSet = tmpSet
	b.mu.Unlock()
}

func (b *BlockManager) StartScheduler(stopCh <-chan struct{}) {
	// domain blocklists update once at start
	go b.UpdateNow()
	// geoip db update once at start
	go b.UpdateGeoIPNow()
	go func() {
		// keep daily schedule for domain blocklists (06:00/12:00/18:00/24:00)
		for {
			next := nextRunTime()
			timer := time.NewTimer(time.Until(next))
			select {
			case <-timer.C:
				b.UpdateNow()
			case <-stopCh:
				if !timer.Stop() {
					<-timer.C
				}
				return
			}
		}
	}()
	go func() {
		// geoip update every 4 hours
		ticker := time.NewTicker(4 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.UpdateGeoIPNow()
			case <-stopCh:
				return
			}
		}
	}()
}

func downloadAndExtractDomains(url string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}
	return extractDomainsFromReader(resp.Body)
}

func extractDomainsFromReader(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	tmpSet := make(map[string]struct{}, 10000)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var candidates []string
		if looksLikeIP(fields[0]) && len(fields) > 1 {
			candidates = fields[1:]
		} else {
			candidates = []string{fields[0]}
		}
		for _, c := range candidates {
			d := normalizeDomain(c)
			if d != "" {
				tmpSet[d] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tmpSet))
	for d := range tmpSet {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

func looksLikeIP(s string) bool {
	if strings.Count(s, ":") >= 2 {
		return true
	}
	if strings.Count(s, ".") == 3 {
		return true
	}
	return false
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "*.")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return ""
		}
	}
	return s
}

func safeFilenameFromURL(u string) string {
	h := sha1.Sum([]byte(u))
	return hex.EncodeToString(h[:])
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if _, err := w.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func nextRunTime() time.Time {
	now := time.Now()
	hours := []int{6, 12, 18, 24}
	for _, h := range hours {
		var t time.Time
		if h == 24 {
			t = time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		} else {
			t = time.Date(now.Year(), now.Month(), now.Day(), h, 0, 0, 0, now.Location())
		}
		if t.After(now) {
			return t
		}
	}
	return time.Date(now.Year(), now.Month(), now.Day()+1, 6, 0, 0, 0, now.Location())
}

func buildNXDomainResponse(req []byte) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: h.ID, Response: true, Authoritative: false, RCode: dnsmessage.RCodeNameError},
		Questions: []dnsmessage.Question{q},
	}
	return msg.Pack()
}

// ---- GeoIP2 support ----

// UpdateGeoIPNow downloads the GeoIP2 mmdb and swaps it atomically.
func (b *BlockManager) UpdateGeoIPNow() {
	if b.geoipURL == "" {
		return
	}
	tmpPath := b.geoDBPath + ".tmp"
	if err := b.downloadFile(b.geoipURL, tmpPath); err != nil {
		return
	}
	_ = os.Rename(tmpPath, b.geoDBPath)
	// open and swap in memory
	db, err := geoip2.Open(b.geoDBPath)
	if err != nil {
		return
	}
	b.mu.Lock()
	if b.geoDB != nil {
		_ = b.geoDB.Close()
	}
	b.geoDB = db
	b.geoDBReady = true
	b.mu.Unlock()
}

func (b *BlockManager) downloadFile(url, outPath string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// CountryForIP returns ISO code and Chinese name if available.
func (b *BlockManager) CountryForIP(ipStr string) (string, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", ""
	}
	b.mu.RLock()
	ready := b.geoDBReady
	db := b.geoDB
	b.mu.RUnlock()
	if !ready {
		return "", ""
	}
	code, zh := lookupCountryZH(db, ip)
	return code, zh
}

// IsClientAllowed returns whether client is allowed based on country whitelist.
func (b *BlockManager) IsClientAllowed(ipStr string) (bool, string, string) {
	code, zh := b.CountryForIP(ipStr)
	switch code {
	case "CN", "HK", "SG", "JP":
		return true, code, zhNameOrDefault(code, zh)
	default:
		if code == "" {
			return false, code, ""
		}
		return false, code, zhNameOrDefault(code, zh)
	}
}

// Helper wrappers to avoid heavy imports in signatures
type geoip2DB interface{ Close() error }

func geoip2Open(path string) (geoip2DB, error) {
	// use geoip2 library
	return geoip2.Open(path)
}

func lookupCountryZH(db geoip2DB, ip net.IP) (string, string) { return queryCountry(db, ip) }

func zhNameOrDefault(code, zh string) string {
	if zh != "" {
		return zh
	}
	switch code {
	case "CN":
		return "中国"
	case "HK":
		return "中国香港"
	case "SG":
		return "新加坡"
	case "JP":
		return "日本"
	default:
		return code
	}
}

// queryCountry uses a concrete geoip2.Reader via type assertion.
func queryCountry(db geoip2DB, ip net.IP) (string, string) {
	r, ok := db.(*geoip2.Reader)
	if !ok {
		return "", ""
	}
	rec, err := r.Country(ip)
	if err != nil || rec == nil || rec.Country.IsoCode == "" {
		if IsPrivateIP(ip) {
			return "Iner", fmt.Sprintf("内网IP %s", ip.String())
		}
		return "", ""
	}
	code := rec.Country.IsoCode
	zh := rec.Country.Names["zh-CN"]
	if zh == "" {
		zh = rec.Country.Names["zh"]
	}
	return code, zh
}
func IsPrivateIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	customPrivateIPRanges := []*net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("100.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
	}
	for _, ipStr := range customPrivateIPRanges {
		if ipStr.Contains(ip) {
			return true
		}
	}
	return false
}
