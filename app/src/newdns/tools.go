package newdns

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var DomainStringChecker = regexp.MustCompile("^[a-zA-Z0-9-.]+$")

func ValidIP(s string) (bool, uint8) {
	ip := net.ParseIP(s)
	if ip == nil {
		return false, 0
	}
	if ip.To4() != nil {
		return true, 1
	}
	return true, 2
}

func SimpleNormalizeDomain(s string) string {
	domain := strings.TrimSpace(s)
	domain = strings.ToLower(domain)
	domain = strings.Trim(domain, ".")
	return domain
}

func NormailizeDomain(s string) (string, *regexp.Regexp, error) {
	result := SimpleNormalizeDomain(s)
	result = strings.TrimPrefix(result, "^")
	result = strings.TrimSuffix(result, "$")
	result = strings.TrimPrefix(result, "*.")
	result = strings.TrimPrefix(result, "*")
	if result == "" || strings.ContainsAny(result, "*") || !DomainStringChecker.MatchString(result) {
		return "", nil, fmt.Errorf("域名处理后为空或仍然包含 * 或不符合域名正则")
	}
	complied, err := regexp.Compile("^.*" + regexp.QuoteMeta(result) + "$")
	if err != nil {
		return "", nil, fmt.Errorf("域名无法被编译为正则表达式: %s", result)
	}
	return result, complied, nil
}

func NewHttpClient(verifySSL bool) *http.Client {
	var useSSL = false
	if verifySSL == true {
		useSSL = true
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: useSSL}},
		Timeout: 30 * time.Second,
	}

}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
func FileRemove(path string) error {
	if !FileExists(path) {
		return nil
	}
	return os.Remove(path)
}
func FileRename(oldPath, newPath string) error {
	if FileExists(oldPath) {
		deleteErr := FileRemove(oldPath)
		if deleteErr != nil {
			return deleteErr
		}
		return os.Rename(oldPath, newPath)
	}
	return nil
}
