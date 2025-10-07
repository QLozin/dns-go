package test

import (
	"fmt"
	"net"
	"os"
	"time"
)

func check_technitium_main() {
	// 验证Technitium DNS服务器是否在运行
	checkServerStatus("100.90.80.129:5353")

	// 测试基本DNS查询是否能正常工作
	testBasicDNSQuery("100.90.80.129:5353")
}

// 检查服务器状态
func checkServerStatus(address string) {
	fmt.Println("=== 检查Technitium DNS服务器状态 ===")
	conn, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		fmt.Printf("无法连接到Technitium DNS服务器 %s: %v\n", address, err)
		fmt.Println("请确保Technitium DNS服务器正在运行并监听在5353端口")
	} else {
		fmt.Printf("成功连接到Technitium DNS服务器 %s\n", address)
		conn.Close()
	}
	fmt.Println("=== 检查完成 ===\n")
}

// 测试基本DNS查询
func testBasicDNSQuery(address string) {
	fmt.Println("=== 测试基本DNS查询 ===")

	// 创建一个简单的DNS查询（A记录查询 google.com）
	// 这个查询不包含ECS扩展，仅用于测试基本连接
	dnsQuery := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags (Standard query)
		0x00, 0x01, // QDCount (1 question)
		0x00, 0x00, // ANCount (0 answers)
		0x00, 0x00, // NSCount (0 authority records)
		0x00, 0x00, // ARCount (0 additional records)
		// 问题部分: google.com A记录
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // 根域名结束
		0x00, 0x01, // QType (A record)
		0x00, 0x01, // QClass (IN)
	}

	// 发送查询
	conn, err := net.Dial("udp", address)
	if err != nil {
		fmt.Printf("无法连接到Technitium DNS服务器: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// 设置写超时
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	written, err := conn.Write(dnsQuery)
	if err != nil {
		fmt.Printf("发送DNS查询失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("发送了 %d 字节的DNS查询\n", written)

	// 设置读超时
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 512)
	responseLen, err := conn.Read(response)
	if err != nil {
		fmt.Printf("读取DNS响应失败: %v\n", err)
		fmt.Println("这表明Technitium DNS服务器可能没有在监听5353端口，或者配置不正确")
	} else {
		fmt.Printf("收到了 %d 字节的DNS响应\n", responseLen)
		fmt.Println("基本DNS查询成功，Technitium服务器正在运行")
		// 检查响应标志
		flags := (uint16(response[2]) << 8) | uint16(response[3])
		rcode := flags & 0x000F
		fmt.Printf("响应状态码 (RCODE): %d\n", rcode)
		if rcode == 0 {
			fmt.Println("DNS查询成功响应")
		} else {
			fmt.Printf("DNS查询响应出错，状态码: %d\n", rcode)
		}
	}
	fmt.Println("=== 测试完成 ===")
}
