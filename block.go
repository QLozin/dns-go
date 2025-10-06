package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// 配置结构
type Config struct {
	Block struct {
		URLs      []string `toml:"urls"`
		WhiteList []string `toml:"white_list"`
	} `toml:"block"`
}

// 域名过滤器
type DomainFilter struct {
	blockedDomains    map[string]struct{} // 封锁域名映射，用于O(1)查找
	whiteListPatterns []*regexp.Regexp    // 白名单正则表达式列表
	mutex             sync.RWMutex        // 读写锁保护并发访问
}

var (
	// 全局域名过滤器实例
	domainFilter *DomainFilter
	// 单例锁
	filterOnce sync.Once
)

// 初始化域名过滤器
func InitDomainFilter(configPath string) error {
	var err error
	filterOnce.Do(func() {
		domainFilter = &DomainFilter{
			blockedDomains:    make(map[string]struct{}),
			whiteListPatterns: make([]*regexp.Regexp, 0),
		}
		err = domainFilter.loadConfig(configPath)
	})
	return err
}

// 加载配置文件
func (df *DomainFilter) loadConfig(configPath string) error {
	var config Config
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	if _, err := toml.NewDecoder(file).Decode(&config); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// 确保block目录存在
	if err := os.MkdirAll("./block", 0755); err != nil {
		return fmt.Errorf("failed to create block directory: %v", err)
	}

	// 下载配置的URL文件
	var downloadedFiles []string
	for _, url := range config.Block.URLs {
		filename := filepath.Base(url)
		if !strings.HasSuffix(filename, ".txt") {
			filename += ".txt"
		}
		filepath := filepath.Join("./block", filename)
		if err := df.downloadFile(url, filepath); err != nil {
			fmt.Printf("Warning: Failed to download %s: %v\n", url, err)
			continue
		}
		downloadedFiles = append(downloadedFiles, filepath)
	}

	// 清理和合并文件
	mergedFile := "./block/merged_domains.txt"
	if err := df.cleanAndMergeFiles(downloadedFiles, mergedFile); err != nil {
		return fmt.Errorf("failed to clean and merge files: %v", err)
	}

	// 加载封锁域名
	if err := df.loadBlockedDomains(mergedFile); err != nil {
		return fmt.Errorf("failed to load blocked domains: %v", err)
	}

	// 编译白名单正则表达式
	if err := df.compileWhiteListPatterns(config.Block.WhiteList); err != nil {
		return fmt.Errorf("failed to compile white list patterns: %v", err)
	}

	return nil
}

// 下载文件
func (df *DomainFilter) downloadFile(url, filepath string) error {
	// 创建一个自定义的HTTP客户端，忽略证书验证
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status: %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// 清理和合并文件
func (df *DomainFilter) cleanAndMergeFiles(filepaths []string, outputPath string) error {
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	defer writer.Flush()

	// 用于跟踪已处理的域名，避免重复
	processedDomains := make(map[string]struct{})

	for _, filepath := range filepaths {
		file, err := os.Open(filepath)
		if err != nil {
			fmt.Printf("Warning: Failed to open file %s: %v\n", filepath, err)
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// 跳过空行和注释行
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// 处理hosts格式文件（IP 域名）
			parts := strings.Fields(line)
			var domain string
			if len(parts) >= 2 {
				// 对于hosts格式，取第二个部分作为域名
				domain = parts[1]
			} else {
				// 对于只有域名的格式，直接使用
				domain = line
			}

			// 确保域名不为空且不重复
			if domain != "" {
				domain = strings.ToLower(domain) // 转换为小写以保证一致性
				if _, exists := processedDomains[domain]; !exists {
					processedDomains[domain] = struct{}{}
					if _, err := writer.WriteString(domain + "\n"); err != nil {
						return fmt.Errorf("failed to write to output file: %v", err)
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Warning: Error reading file %s: %v\n", filepath, err)
		}
	}

	return nil
}

// 加载封锁域名
func (df *DomainFilter) loadBlockedDomains(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open blocked domains file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	df.mutex.Lock()
	defer df.mutex.Unlock()

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			df.blockedDomains[domain] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocked domains file: %v", err)
	}

	return nil
}

// 编译白名单正则表达式
func (df *DomainFilter) compileWhiteListPatterns(patterns []string) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	df.whiteListPatterns = make([]*regexp.Regexp, 0, len(patterns))

	for _, pattern := range patterns {
		// 将通配符模式转换为正则表达式
		regexPattern := pattern
		regexPattern = strings.ReplaceAll(regexPattern, ".", "\\.")
		regexPattern = strings.ReplaceAll(regexPattern, "*", ".*")
		regexPattern = "^" + regexPattern + "$"

		re, err := regexp.Compile(regexPattern)
		if err != nil {
			return fmt.Errorf("failed to compile white list pattern '%s': %v", pattern, err)
		}

		df.whiteListPatterns = append(df.whiteListPatterns, re)
	}

	return nil
}

// 检查域名是否在白名单中
func (df *DomainFilter) IsInWhiteList(domain string) bool {
	df.mutex.RLock()
	defer df.mutex.RUnlock()

	for _, pattern := range df.whiteListPatterns {
		if pattern.MatchString(domain) {
			return true
		}
	}

	return false
}

// 检查域名是否在封锁名单中
func (df *DomainFilter) IsBlocked(domain string) bool {
	df.mutex.RLock()
	defer df.mutex.RUnlock()

	// 首先检查精确匹配
	_, exists := df.blockedDomains[domain]
	if exists {
		return true
	}

	// 检查子域名匹配（例如，block.com 会阻止 a.block.com）
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		subdomain := strings.Join(parts[i:], ".")
		if _, exists := df.blockedDomains[subdomain]; exists {
			return true
		}
	}

	return false
}

// 获取全局域名过滤器实例
func GetDomainFilter() *DomainFilter {
	return domainFilter
}

// 重新加载域名过滤器（不影响主程序运行）
func ReloadDomainFilter(configPath string) {
	// 创建一个新的域名过滤器实例
	newFilter := &DomainFilter{
		blockedDomains:    make(map[string]struct{}),
		whiteListPatterns: make([]*regexp.Regexp, 0),
	}

	// 尝试加载配置
	if err := newFilter.loadConfig(configPath); err != nil {
		log.Printf("Warning: Failed to reload domain filter: %v", err)
		return // 加载失败，不替换现有过滤器
	}

	// 加载成功，替换全局过滤器
	filterOnce.Do(func() {})
	domainFilter = newFilter
	log.Printf("Domain filter reloaded successfully")
}

// 启动定时更新任务
func StartDomainFilterUpdateTask(configPath string) {
	// 定义更新时间点（小时）
	updateHours := []int{6, 12, 18, 24} // 早晨6点、中午12点、傍晚18点、午夜24点

	// 立即执行一次更新
	doScheduledUpdate(configPath)

	// 启动定时任务
	go func() {
		for {
			// 计算下一个更新时间
			now := time.Now()
			var nextUpdateTime time.Time
			found := false

			// 查找今天剩余的更新时间点
			for _, hour := range updateHours {
				targetTime := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
				if hour == 24 {
					targetTime = targetTime.AddDate(0, 0, 1)
					targetTime = targetTime.Add(-time.Second)
				}
				if targetTime.After(now) {
					nextUpdateTime = targetTime
					found = true
					break
				}
			}

			// 如果今天没有剩余更新时间点，则使用明天第一个时间点
			if !found {
				tomorrow := now.AddDate(0, 0, 1)
				hour := updateHours[0]
				nextUpdateTime = time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), hour, 0, 0, 0, tomorrow.Location())
			}

			// 计算等待时间
			waitDuration := nextUpdateTime.Sub(now)
			log.Printf("Next domain filter update scheduled at: %s", nextUpdateTime.Format("2006-01-02 15:04:05"))

			// 等待到下一个更新时间
			timer := time.NewTimer(waitDuration)
			<-timer.C
			doScheduledUpdate(configPath)
		}
	}()
}

// 执行定时更新
func doScheduledUpdate(configPath string) {
	log.Printf("Starting scheduled domain filter update...")
	ReloadDomainFilter(configPath)
	log.Printf("Scheduled domain filter update completed")
}
