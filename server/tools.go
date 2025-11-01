package server

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
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
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: verifySSL}},
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
		answers = append(answers, StructToString(answer))
	}
	return rcode, answers, nil
}

func PtrFinding(ptr reflect.Value) reflect.Value {
	if ptr.Kind() == reflect.Ptr {
		if ptr.IsNil() {
			return reflect.Value{}
		}
		return PtrFinding(ptr.Elem())
	}
	return ptr
}

func StructToString(v interface{}) string {
	if v == nil || reflect.ValueOf(v).IsNil() {
		return "<nil>"
	}
	val := reflect.ValueOf(v)
	val = PtrFinding(val)
	if !val.IsValid() {
		return "<nil>"
	}
	if val.Kind() != reflect.Struct {
		return fmt.Sprintf("%v", v)
	}
	var result []string
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldName := typ.Field(i).Name
		if !field.CanInterface() {
			continue
		}
		dereference := PtrFinding(field)
		var fieldValue string
		if !dereference.IsValid() {
			fieldValue = "<nil>"
		} else {
			if str, ok := field.Interface().(fmt.Stringer); ok {
				fieldValue = str.String()
			} else {
				fieldValue = fmt.Sprintf("%v", dereference.Interface())
			}
		}

		result = append(result, fmt.Sprintf("%s:%s", fieldName, fieldValue))
	}

	return strings.Join(result, " ")
}

// FormatTime 将 RFC3339Nano 格式的时间转换为人类可读格式
func (d DnsLog) FormatTime() string {
	if d.Time == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339Nano, d.Time); err == nil {
		return t.Format("2006-01-02 15:04:05.999999999")
	}
	return d.Time
}

func TimeNow() string {
	return time.Now().Format(time.RFC3339Nano)
}

// BytesToHex 将字节数组转换为十六进制字符串
// 如果字节数组太长（超过maxBytes），只显示前maxBytes字节
func BytesToHex(data []byte, maxBytes int) string {
	if len(data) == 0 {
		return "(空)"
	}
	displayLen := len(data)
	if maxBytes > 0 && displayLen > maxBytes {
		displayLen = maxBytes
	}
	hexStr := hex.EncodeToString(data[:displayLen])
	if len(data) > maxBytes {
		return fmt.Sprintf("%s...(总共%d字节)", hexStr, len(data))
	}
	return hexStr
}
