package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type BlockManager struct {
	mu                sync.RWMutex
	blacklistExactSet map[string]struct{}
	whitelistRegexps  []*regexp.Regexp
	sourceURLs        []string
	whitelistPatterns []string
	dataDir           string
}

func NewBlockManager(envPath string) *BlockManager {
	cfg, err := LoadConfig(envPath)
	var urls []string
	var whitelist []string
	if err == nil && cfg != nil {
		urls = append(urls, cfg.Block.URLs...)
		whitelist = append(whitelist, cfg.Block.WhiteList...)
	}
	bm := &BlockManager{
		blacklistExactSet: make(map[string]struct{}),
		whitelistRegexps:  nil,
		sourceURLs:        urls,
		whitelistPatterns: whitelist,
		dataDir:           filepath.Join("block"),
	}
	_ = os.MkdirAll(bm.dataDir, 0o755)
	bm.compileWhitelist()
	return bm
}

func (b *BlockManager) compileWhitelist() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.whitelistRegexps = b.whitelistRegexps[:0]
	for _, pat := range b.whitelistPatterns {
		// Convert shell-like "*.example.com" to regex if it doesn't look like a regex already
		rx := pat
		if !strings.HasPrefix(rx, "^") && !strings.HasSuffix(rx, "$") {
			// escape dots, replace * with .*
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
	// Exact or parent-domain match
	// e.g., block example.com blocks sub.example.com
	labels := strings.Split(d, ".")
	for i := 0; i < len(labels); i++ {
		cand := strings.Join(labels[i:], ".")
		if _, ok := set[cand]; ok {
			return true
		}
	}
	return false
}

// Update now: download, preprocess, save, reload memory. Errors are swallowed.
func (b *BlockManager) UpdateNow() {
	if len(b.sourceURLs) == 0 {
		return
	}

	tmpSet := make(map[string]struct{}, 1_000_000)
	for _, u := range b.sourceURLs {
		domains, err := downloadAndExtractDomains(u)
		if err != nil {
			continue // ignore failures
		}
		// Save to file for inspection
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

	// Swap into memory
	b.mu.Lock()
	b.blacklistExactSet = tmpSet
	b.mu.Unlock()
}

// Scheduler: run at 06:00, 12:00, 18:00, 24:00 local time, and once immediately.
func (b *BlockManager) StartScheduler(stopCh <-chan struct{}) {
	// Immediate update (non-blocking)
	go b.UpdateNow()

	go func() {
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
}

// Helpers

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
		// Hosts format: leading IP then one or more domains
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
	// stable order for file output
	out := make([]string, 0, len(tmpSet))
	for d := range tmpSet {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

func looksLikeIP(s string) bool {
	if strings.Count(s, ":") >= 2 { // IPv6 heuristic
		return true
	}
	// IPv4 heuristic
	if strings.Count(s, ".") == 3 {
		return true
	}
	return false
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	// drop leading ip-like tokens or invalid chars
	if s == "" {
		return ""
	}
	// Remove leading wildcard '*.'
	s = strings.TrimPrefix(s, "*.")
	// Ensure only valid domain runes (basic)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return ""
		}
	}
	return s
}

func safeFilenameFromURL(u string) string {
	// use sha1 of url to avoid filesystem issues while keeping deterministic name
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
		// 24 means next day 00:00
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
	// fallback: next day 06:00
	return time.Date(now.Year(), now.Month(), now.Day()+1, 6, 0, 0, 0, now.Location())
}

// Build NXDOMAIN response for a given request. Returns nil on parse error.
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
		Header: dnsmessage.Header{
			ID:            h.ID,
			Response:      true,
			Authoritative: false,
			RCode:         dnsmessage.RCodeNameError,
		},
		Questions: []dnsmessage.Question{q},
	}
	return msg.Pack()
}

// Ensure compile
var _ = errors.New
