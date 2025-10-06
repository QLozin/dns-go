package main

import (
	"encoding/binary"
	"fmt"
)

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
	TypeA      RecordType = 1  // IPv4地址记录
	TypeNS     RecordType = 2  // 名称服务器记录
	TypeCNAME  RecordType = 5  // 规范名称记录
	TypeSOA    RecordType = 6  // 起始授权记录
	TypeWKS    RecordType = 11 // 熟知服务记录
	TypePTR    RecordType = 12 // 指针记录
	TypeHINFO  RecordType = 13 // 主机信息记录
	TypeMINFO  RecordType = 14 // 邮箱信息记录
	TypeMX     RecordType = 15 // 邮件交换记录
	TypeTXT    RecordType = 16 // 文本记录
	TypeAAAA   RecordType = 28 // IPv6地址记录
	TypeSRV    RecordType = 33 // 服务定位器记录
	TypeDS     RecordType = 43 // DNSSEC签名记录
	TypeDNSKEY RecordType = 48 // DNSSEC密钥记录
	TypeRRSIG  RecordType = 58 // 资源记录签名
	TypeHTTPS  RecordType = 65 // HTTPS记录
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

// 检查DNS消息中是否包含EDNS Client Subnet扩展
func hasEDNSClientSubnet(data []byte) bool {
	// 基本检查
	if len(data) < 12 {
		return false
	}

	// 解析头部
	header := DNSHeader{
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	// 没有附加记录，肯定没有ECS
	if header.ARCount == 0 {
		return false
	}

	// 跳过问题部分
	position := 12
	qdCount := binary.BigEndian.Uint16(data[4:6])
	for i := 0; i < int(qdCount); i++ {
		// 跳过域名
		for {
			if position >= len(data) {
				return false
			}
			length := int(data[position])
			position++
			if length == 0 {
				break
			} else if length&0xC0 == 0xC0 {
				// 指针
				position++
				break
			} else {
				position += length
			}
		}
		// 跳过QType和QClass
		position += 4
	}

	// 检查附加记录
	for i := 0; i < int(header.ARCount); i++ {
		// 跳过域名
		for {
			if position >= len(data) {
				return false
			}
			length := int(data[position])
			position++
			if length == 0 {
				break
			} else if length&0xC0 == 0xC0 {
				// 指针
				position++
				break
			} else {
				position += length
			}
		}

		// 检查是否为OPT记录（类型41）
		if position+2 > len(data) {
			return false
		}
		recordType := binary.BigEndian.Uint16(data[position : position+2])
		position += 10 // 跳过类型、类、TTL

		// 检查记录是否为OPT类型（41）
		if recordType == 41 {
			// 检查数据长度
			if position+2 > len(data) {
				return false
			}
			dataLen := binary.BigEndian.Uint16(data[position : position+2])
			position += 2

			// 检查数据部分是否包含ECS选项（选项码8）
			ecsEnd := position + int(dataLen)
			for position < ecsEnd {
				if position+4 > len(data) {
					break
				}
				optionCode := binary.BigEndian.Uint16(data[position : position+2])
				optionLen := binary.BigEndian.Uint16(data[position+2 : position+4])
				position += 4

				// 如果找到ECS选项（选项码8），返回true
				if optionCode == 8 {
					return true
				}

				position += int(optionLen)
			}
		}
	}

	return false
}
