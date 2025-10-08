package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"
)

// DNSHeader 表示DNS消息头
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// 添加EDNS Client Subnet扩展到DNS请求
func addEDNSClientSubnet(data []byte, clientIP net.IP) ([]byte, error) {
	fmt.Println("=== 开始添加EDNS Client Subnet扩展 ===")
	fmt.Printf("原始数据长度: %d 字节\n", len(data))
	fmt.Printf("客户端IP: %s\n", clientIP)

	// 检查数据长度是否足够
	if len(data) < 12 {
		fmt.Println("错误: DNS数据太短")
		return nil, fmt.Errorf("DNS message too short")
	}

	// 复制原始数据
	newData := make([]byte, len(data))
	copy(newData, data)
	fmt.Println("复制原始数据完成")

	// 解析头部
	header := DNSHeader{
		ID:      binary.BigEndian.Uint16(newData[0:2]),
		Flags:   binary.BigEndian.Uint16(newData[2:4]),
		QDCount: binary.BigEndian.Uint16(newData[4:6]),
		ANCount: binary.BigEndian.Uint16(newData[6:8]),
		NSCount: binary.BigEndian.Uint16(newData[8:10]),
		ARCount: binary.BigEndian.Uint16(newData[10:12]),
	}

	fmt.Printf("DNS头部信息:\n")
	fmt.Printf("  ID: 0x%04X\n", header.ID)
	fmt.Printf("  Flags: 0x%04X\n", header.Flags)
	fmt.Printf("  QDCount: %d\n", header.QDCount)
	fmt.Printf("  ANCount: %d\n", header.ANCount)
	fmt.Printf("  NSCount: %d\n", header.NSCount)
	fmt.Printf("  ARCount: %d\n", header.ARCount)

	// 增加附加记录计数
	header.ARCount++
	binary.BigEndian.PutUint16(newData[10:12], header.ARCount)
	fmt.Printf("更新ARCount: %d → %d\n", header.ARCount-1, header.ARCount)

	// 创建EDNS0记录
	var ednsRecord []byte

	// 名称字段（根域名，长度为0）
	ednsRecord = append(ednsRecord, 0x00)
	fmt.Println("  添加根域名(0x00)")

	// 类型：OPT (41)
	ednsRecord = append(ednsRecord, 0x00, 0x29)
	fmt.Printf("  添加记录类型: OPT (0x%04X)\n", 41)

	// UDP负载大小：4096
	ednsRecord = append(ednsRecord, 0x00, 0xFF)
	fmt.Printf("  添加UDP负载大小: 4096\n")

	// 扩展RCODE和EDNS版本
	ednsRecord = append(ednsRecord, 0x00, 0x00)
	fmt.Printf("  添加扩展RCODE和EDNS版本: 0x0000\n")

	// Z字段（保留）
	ednsRecord = append(ednsRecord, 0x00, 0x00)
	fmt.Printf("  添加Z字段: 0x0000\n")

	// 数据长度 - 后续会更新
	dataLengthPos := len(ednsRecord)
	ednsRecord = append(ednsRecord, 0x00, 0x00) // 临时值，稍后更新
	fmt.Printf("  预留数据长度位置: %d\n", dataLengthPos)

	// 客户端子网选项
	// 选项码：CLIENT_SUBNET (8)
	ednsRecord = append(ednsRecord, 0x00, 0x08)
	fmt.Printf("  添加选项码: CLIENT_SUBNET (8)\n")

	// 选项长度 - 后续会更新
	optionLengthPos := len(ednsRecord)
	ednsRecord = append(ednsRecord, 0x00, 0x00) // 临时值，稍后更新
	fmt.Printf("  预留选项长度位置: %d\n", optionLengthPos)

	// 地址族：IPv4 (1) 或 IPv6 (2)
	var family uint16
	var sourceNetmask uint8
	var scopeNetmask uint8
	var addressBytes []byte
	var totalOptionLength int

	if ipv4 := clientIP.To4(); ipv4 != nil {
		family = 1
		sourceNetmask = 24 // 使用/24子网掩码
		scopeNetmask = 0
		addressBytes = ipv4[:3] // 只保留前3个字节
		totalOptionLength = 7   // 选项数据总长度：2(family) + 1(source) + 1(scope) + 3(address)
		fmt.Printf("  IPv4地址: %s, 网络: %d.%d.%d.0/24\n",
			clientIP.String(), ipv4[0], ipv4[1], ipv4[2])
		fmt.Printf("  地址族: IPv4 (1), 源掩码: 24, 作用域掩码: 0\n")
		fmt.Printf("  IPv4前3字节: % X\n", addressBytes)
	} else {
		family = 2
		sourceNetmask = 64 // IPv6使用/64子网掩码
		scopeNetmask = 0
		ipv6 := clientIP.To16()
		addressBytes = ipv6[:8] // 只保留前8个字节
		totalOptionLength = 11  // 选项数据总长度：2(family) + 1(source) + 1(scope) + 8(address)
		fmt.Printf("  IPv6地址: %s\n", clientIP.String())
		fmt.Printf("  地址族: IPv6 (2), 源掩码: 64, 作用域掩码: 0\n")
		fmt.Printf("  IPv6前8字节: % X\n", addressBytes)
	}

	// 更新选项长度
	ednsRecord[optionLengthPos] = byte(totalOptionLength >> 8)
	ednsRecord[optionLengthPos+1] = byte(totalOptionLength & 0xFF)
	fmt.Printf("  更新选项长度: %d字节\n", totalOptionLength)

	// 添加地址族、子网掩码和地址
	ednsRecord = append(ednsRecord, byte(family>>8), byte(family&0xFF))
	ednsRecord = append(ednsRecord, sourceNetmask)
	ednsRecord = append(ednsRecord, scopeNetmask)
	ednsRecord = append(ednsRecord, addressBytes...)

	// 更新数据长度
	dataLength := totalOptionLength + 4 // 选项码(2) + 选项长度(2) + 选项数据
	ednsRecord[dataLengthPos] = byte(dataLength >> 8)
	ednsRecord[dataLengthPos+1] = byte(dataLength & 0xFF)
	fmt.Printf("  更新数据长度: %d字节\n", dataLength)

	// 将EDNS记录添加到消息末尾
	newData = append(newData, ednsRecord...)
	fmt.Printf("EDNS记录长度: %d字节\n", len(ednsRecord))
	fmt.Printf("添加ECS后的总长度: %d字节\n", len(newData))
	fmt.Println("=== 添加完成 ===")

	return newData, nil
}

// 检查DNS消息中是否包含EDNS Client Subnet扩展
func hasEDNSClientSubnet(data []byte) bool {
	fmt.Println("=== 开始检测EDNS Client Subnet扩展 ===")
	fmt.Printf("数据总长度: %d 字节\n", len(data))
	fmt.Printf("DNS头部信息:\n")
	fmt.Printf("  ID: 0x%04X\n", binary.BigEndian.Uint16(data[0:2]))
	fmt.Printf("  Flags: 0x%04X\n", binary.BigEndian.Uint16(data[2:4]))
	fmt.Printf("  QDCount: %d\n", binary.BigEndian.Uint16(data[4:6]))
	fmt.Printf("  ANCount: %d\n", binary.BigEndian.Uint16(data[6:8]))
	fmt.Printf("  NSCount: %d\n", binary.BigEndian.Uint16(data[8:10]))
	fmt.Printf("  ARCount: %d\n", binary.BigEndian.Uint16(data[10:12]))

	// 基本检查
	if len(data) < 12 {
		fmt.Println("DNS消息太短，不包含完整头部")
		return false
	}

	// 解析头部
	header := DNSHeader{
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	// 没有附加记录，肯定没有ECS
	if header.ARCount == 0 {
		fmt.Println("没有附加记录，不包含ECS扩展")
		return false
	}

	// 跳过问题部分
	position := 12
	qdCount := binary.BigEndian.Uint16(data[4:6])
	fmt.Printf("跳过%d个问题记录...\n", qdCount)
	for i := 0; i < int(qdCount); i++ {
		// 跳过域名
		startPos := position
		for {
			if position >= len(data) {
				fmt.Println("解析域名时超出数据范围")
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
		fmt.Printf("  问题%d占用了%d字节\n", i+1, position-startPos)
	}

	fmt.Printf("当前位置: %d\n", position)
	// 检查附加记录
	fmt.Printf("检查%d个附加记录...\n", header.ARCount)
	for i := 0; i < int(header.ARCount); i++ {
		startPos := position
		// 跳过域名
		for {
			if position >= len(data) {
				fmt.Println("解析附加记录域名时超出数据范围")
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
			fmt.Println("记录类型字段超出数据范围")
			return false
		}
		recordType := binary.BigEndian.Uint16(data[position : position+2])
		fmt.Printf("  附加记录%d: 类型=0x%04X\n", i+1, recordType)

		// 检查记录是否为OPT类型（41）
		if recordType == 41 {
			fmt.Println("  找到OPT记录，可能包含ECS扩展")
			// 跳过类、TTL
			position += 8

			// 检查数据长度
			if position+2 > len(data) {
				fmt.Println("数据长度字段超出数据范围")
				return false
			}
			dataLen := binary.BigEndian.Uint16(data[position : position+2])
			position += 2
			fmt.Printf("  OPT记录数据长度: %d字节\n", dataLen)

			// 检查数据部分是否包含ECS选项（选项码8）
			ecsEnd := position + int(dataLen)
			fmt.Printf("  检查OPT记录数据部分（位置%d-%d）\n", position, ecsEnd-1)
			for position < ecsEnd {
				if position+4 > len(data) {
					fmt.Println("选项字段超出数据范围")
					break
				}
				optionCode := binary.BigEndian.Uint16(data[position : position+2])
				optionLen := binary.BigEndian.Uint16(data[position+2 : position+4])
				fmt.Printf("    选项: 代码=0x%04X, 长度=%d字节\n", optionCode, optionLen)
				position += 4

				// 如果找到ECS选项（选项码8），返回true
				if optionCode == 8 {
					fmt.Println("    找到EDNS Client Subnet选项！")
					// 解析ECS选项内容
					if position+2 <= len(data) {
						family := binary.BigEndian.Uint16(data[position : position+2])
						sourceNetmask := data[position+2]
						scopeNetmask := data[position+3]
						fmt.Printf("    ECS选项详情: 地址族=0x%04X, 源掩码=%d, 作用域掩码=%d\n",
							family, sourceNetmask, scopeNetmask)
					}
					return true
				}

				position += int(optionLen)
			}
		} else {
			// 不是OPT记录，跳过剩余部分
			// 跳过类、TTL、RDLength和RData
			if position+8 > len(data) {
				fmt.Println("非OPT记录字段超出数据范围")
				return false
			}
			rdLength := binary.BigEndian.Uint16(data[position+6 : position+8])
			position += 8 + int(rdLength)
		}
		fmt.Printf("  附加记录%d共占用了%d字节\n", i+1, position-startPos)
	}

	fmt.Println("未找到EDNS Client Subnet扩展")
	fmt.Println("=== 检测结束 ===")
	return false
}

// 发送DNS查询并验证ECS功能
func testECSForwarding(clientIP string, targetDNS string, domain string) {
	// 解析客户端IP
	clientIPAddr := net.ParseIP(clientIP)
	if clientIPAddr == nil {
		log.Fatalf("Invalid client IP address: %s", clientIP)
	}

	// 创建一个简单的DNS查询数据（查询A记录）
	dnsQuery := createDNSQuery(domain)

	fmt.Println("原始DNS查询长度:", len(dnsQuery))
	fmt.Println("原始DNS查询(前20字节):")
	fmt.Println(hex.Dump(dnsQuery[:min(20, len(dnsQuery))]))

	// 添加EDNS Client Subnet扩展
	dnsWithECS, err := addEDNSClientSubnet(dnsQuery, clientIPAddr)
	if err != nil {
		log.Fatalf("Failed to add EDNS Client Subnet: %v", err)
	}

	fmt.Println("添加ECS后的DNS查询长度:", len(dnsWithECS))
	fmt.Println("添加ECS后的DNS查询(前20字节):")
	fmt.Println(hex.Dump(dnsWithECS[:min(20, len(dnsWithECS))]))

	// 验证ECS扩展是否被正确添加
	hasECS := hasEDNSClientSubnet(dnsWithECS)
	fmt.Printf("DNS查询中是否包含EDNS Client Subnet扩展: %v\n", hasECS)

	// 发送查询到目标DNS服务器
	conn, err := net.Dial("udp", targetDNS)
	if err != nil {
		log.Fatalf("Failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	// 设置写入超时
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	written, err := conn.Write(dnsWithECS)
	if err != nil {
		log.Fatalf("Failed to send DNS query: %v", err)
	}
	fmt.Printf("Sent %d bytes to %s\n", written, targetDNS)

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil {
		log.Fatalf("Failed to read DNS response: %v", err)
	}
	fmt.Printf("Received %d bytes response\n", n)

	// 检查响应中是否包含EDNS记录
	// 注意：响应中不一定会包含ECS选项，这取决于DNS服务器的实现
}

// 创建一个简单的DNS查询
func createDNSQuery(domain string) []byte {
	// 最小DNS查询格式
	// ID: 0x1234
	// Flags: 0x0100 (标准查询)
	// QDCount: 1
	// ANCount, NSCount, ARCount: 0
	// 然后是域名和查询类型/类

	query := make([]byte, 12)                      // 头部
	binary.BigEndian.PutUint16(query[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(query[2:4], 0x0100) // Flags
	binary.BigEndian.PutUint16(query[4:6], 1)      // QDCount

	// 添加域名
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0) // 根域名结束

	// 添加查询类型和类
	query = append(query, 0, 1) // QType: A
	query = append(query, 0, 1) // QClass: IN

	return query
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var strings = struct {
	Split func(string, string) []string
}{Split: func(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i = start - 1
		}
	}
	result = append(result, s[start:])
	return result
}}

func debug_ecs_main() {
	// 测试参数
	clientIP := "27.38.0.132"         // 用户提供的客户端IP
	targetDNS := "100.90.80.129:5353" // Technitium DNS服务器
	domain := "mcs.zijieapi.com"      // 用户查询的域名

	fmt.Printf("测试EDNS Client Subnet功能\n")
	fmt.Printf("客户端IP: %s\n", clientIP)
	fmt.Printf("目标DNS服务器: %s\n", targetDNS)
	fmt.Printf("查询域名: %s\n\n", domain)

	// 执行测试
	testECSForwarding(clientIP, targetDNS, domain)
}
