package main

import "fmt"

// DNS响应码常量
type ResponseCode uint8

const (
    RCodeNoError  ResponseCode = 0  // 无错误条件
    RCodeFormErr  ResponseCode = 1  // 格式错误 - 服务器无法解析请求
    RCodeServFail ResponseCode = 2  // 服务器失败 - 服务器遇到内部错误
    RCodeNXDomain ResponseCode = 3  // 域名不存在 - 域名不存在于被查询区域
    RCodeNotImp   ResponseCode = 4  // 未实现 - 服务器不支持请求的功能
    RCodeRefused  ResponseCode = 5  // 拒绝 - 服务器拒绝执行请求
    RCodeYXDomain ResponseCode = 6  // 域名存在 - 域名已存在
    RCodeYXRRSet  ResponseCode = 7  // 记录集存在 - 记录集已存在
    RCodeNXRRSet  ResponseCode = 8  // 记录集不存在 - 记录集不存在
    RCodeNotAuth  ResponseCode = 9  // 未授权 - 服务器未授权
    RCodeNotZone  ResponseCode = 10 // 不是区域 - 名称不在区域中
)

// DNS记录类型常量
type RecordType uint16

const (
    TypeA     RecordType = 1   // IPv4地址记录
    TypeNS    RecordType = 2   // 名称服务器记录
    TypeCNAME RecordType = 5   // 规范名称记录
    TypeSOA   RecordType = 6   // 起始授权记录
    TypeWKS   RecordType = 11  // 熟知服务记录
    TypePTR   RecordType = 12  // 指针记录
    TypeHINFO RecordType = 13  // 主机信息记录
    TypeMINFO RecordType = 14  // 邮箱信息记录
    TypeMX    RecordType = 15  // 邮件交换记录
    TypeTXT   RecordType = 16  // 文本记录
    TypeAAAA  RecordType = 28  // IPv6地址记录
    TypeSRV   RecordType = 33  // 服务定位器记录
    TypeDS    RecordType = 43  // DNSSEC签名记录
    TypeDNSKEY RecordType = 48 // DNSSEC密钥记录
    TypeRRSIG RecordType = 58  // 资源记录签名
    TypeHTTPS RecordType = 65  // HTTPS记录
)

// 将响应码转换为可读的文本
func responseCodeToString(rcode uint8) string {
    switch ResponseCode(rcode) {
    case RCodeNoError:
        return "NOERROR (0)"
    case RCodeFormErr:
        return "FORMERR (1)"
    case RCodeServFail:
        return "SERVFAIL (2)"
    case RCodeNXDomain:
        return "NXDOMAIN (3)"
    case RCodeNotImp:
        return "NOTIMP (4)"
    case RCodeRefused:
        return "REFUSED (5)"
    case RCodeYXDomain:
        return "YXDOMAIN (6)"
    case RCodeYXRRSet:
        return "YXRRSET (7)"
    case RCodeNXRRSet:
        return "NXRRSET (8)"
    case RCodeNotAuth:
        return "NOTAUTH (9)"
    case RCodeNotZone:
        return "NOTZONE (10)"
    default:
        return fmt.Sprintf("Unknown (%d)", rcode)
    }
}

// 将记录类型转换为可读文本
func recordTypeToString(recordType uint16) string {
    switch RecordType(recordType) {
    case TypeA:
        return "A"
    case TypeNS:
        return "NS"
    case TypeCNAME:
        return "CNAME"
    case TypeSOA:
        return "SOA"
    case TypeWKS:
        return "WKS"
    case TypePTR:
        return "PTR"
    case TypeHINFO:
        return "HINFO"
    case TypeMINFO:
        return "MINFO"
    case TypeMX:
        return "MX"
    case TypeTXT:
        return "TXT"
    case TypeAAAA:
        return "AAAA"
    case TypeSRV:
        return "SRV"
    case TypeDS:
        return "DS"
    case TypeDNSKEY:
        return "DNSKEY"
    case TypeRRSIG:
        return "RRSIG"
    case TypeHTTPS:
        return "HTTPS"
    default:
        return fmt.Sprintf("TYPE%d", recordType)
    }
}