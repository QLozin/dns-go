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

	"golang.org/x/net/dns/dnsmessage"
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

func DnsReqTypeToString(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

func DnsRCodeToString(rcode dnsmessage.RCode) string {
	switch rcode {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", int(rcode))
	}
}

func DnsTypeToString(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

func ResolveDNSResponse(resp []byte) (rcode string, answers []string, err error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(resp)
	if err != nil {
		return "", nil, fmt.Errorf("解析响应头失败: %w", err)
	}
	rcode = DnsRCodeToString(header.RCode)
	for {
		_, err := parser.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return rcode, nil, fmt.Errorf("解析响应问题失败: %w", err)
		}
	}
	for {
		answer, err := parser.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return rcode, nil, fmt.Errorf("解析响应答案失败: %w", err)
		}
		answers = append(answers)
	}
}
