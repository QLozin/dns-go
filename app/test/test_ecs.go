package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
)

func test_ecs_main() {
	// 创建一个简单的DNS查询数据（查询A记录的最小DNS消息）
	// 0x0001: ID
	// 0x0100: 标准查询标志
	// 0x0001: 1个问题
	// 0x0000: 0个回答
	// 0x0000: 0个权威记录
	// 0x0000: 0个附加记录
	// 0x03777777076578616d706c6503636f6d00: 域名 www.example.com.
	// 0x0001: 查询类型 A
	// 0x0001: 查询类 IN
	dnsQuery := []byte{
		0x00, 0x01, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCount
		0x00, 0x00, // ANCount
		0x00, 0x00, // NSCount
		0x00, 0x00, // ARCount
		0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, // www.example
		0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, // .com
		0x00,       // 根域名结束
		0x00, 0x01, // QType: A
		0x00, 0x01, // QClass: IN
	}

	// 模拟客户端IP
	clientIP := net.ParseIP("27.38.0.132")
	if clientIP == nil {
		fmt.Println("Invalid client IP address")
		os.Exit(1)
	}

	// 添加EDNS Client Subnet扩展
	dnsWithECS, err := addEDNSClientSubnet(dnsQuery, clientIP)
	if err != nil {
		fmt.Printf("Failed to add EDNS Client Subnet: %v\n", err)
		os.Exit(1)
	}

	// 打印原始DNS查询和添加ECS后的DNS查询的十六进制表示
	fmt.Println("原始DNS查询:")
	fmt.Println(hex.Dump(dnsQuery))
	fmt.Println("添加EDNS Client Subnet后的DNS查询:")
	fmt.Println(hex.Dump(dnsWithECS))

	// 检查是否成功添加了ECS扩展
	hasECS := checkForECS(dnsWithECS)
	fmt.Printf("DNS查询中是否包含EDNS Client Subnet扩展: %v\n", hasECS)
}

// 检查DNS消息中是否包含EDNS Client Subnet扩展
func checkForECS(data []byte) bool {
	// 基本检查
	if len(data) < 12 {
		return false
	}

	// 解析头部
	header := DNSHeader{
		ID:      0,
		Flags:   0,
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: 0,
		NSCount: 0,
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	// 没有附加记录，肯定没有ECS
	if header.ARCount == 0 {
		return false
	}

	// 跳过问题部分
	position := 12
	for i := 0; i < int(header.QDCount); i++ {
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
