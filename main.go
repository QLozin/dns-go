package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
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

// DNSQuestion 表示DNS查询部分
type DNSQuestion struct {
	Name   string
	QType  uint16
	QClass uint16
}

// DNSRecord 表示DNS记录
type DNSRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	rdata    []byte
}

// DNSLogEntry 表示DNS查询日志条目
type DNSLogEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	ClientIP      string    `json:"client_ip"`
	TransactionID uint16    `json:"transaction_id"`
	DomainName    string    `json:"domain_name"`
	QueryType     uint16    `json:"query_type"`
	QueryClass    uint16    `json:"query_class"`
	Result        string    `json:"result"`
}

var (
	logFile     *os.File
	logMutex    sync.Mutex
	upstreamDNS = "localhost:5353"
)

// 解析DNS消息
func parseDNSMessage(data []byte) (DNSHeader, []DNSQuestion, error) {
	var header DNSHeader
	header.ID = binary.BigEndian.Uint16(data[0:2])
	header.Flags = binary.BigEndian.Uint16(data[2:4])
	header.QDCount = binary.BigEndian.Uint16(data[4:6])
	header.ANCount = binary.BigEndian.Uint16(data[6:8])
	header.NSCount = binary.BigEndian.Uint16(data[8:10])
	header.ARCount = binary.BigEndian.Uint16(data[10:12])

	questions := make([]DNSQuestion, header.QDCount)
	position := 12

	for i := 0; i < int(header.QDCount); i++ {
		name, newPosition, err := parseName(data, position)
		if err != nil {
			return DNSHeader{}, nil, err
		}
		position = newPosition

		questions[i] = DNSQuestion{
			Name:   name,
			QType:  binary.BigEndian.Uint16(data[position : position+2]),
			QClass: binary.BigEndian.Uint16(data[position+2 : position+4]),
		}
		position += 4
	}

	return header, questions, nil
}

// 从DNS响应头中提取响应码
func getResponseCode(flags uint16) uint8 {
	// 响应码在Flags的低4位
	return uint8(flags & 0x000F)
}

// 解析DNS响应中的答案记录
func parseDNSRecords(data []byte, count uint16, position int) ([]DNSRecord, int, error) {
	records := make([]DNSRecord, count)
	currentPosition := position

	for i := 0; i < int(count); i++ {
		// 解析域名
		name, newPosition, err := parseName(data, currentPosition)
		if err != nil {
			return nil, 0, err
		}
		currentPosition = newPosition

		// 解析记录类型、类、TTL和数据长度
		recordType := binary.BigEndian.Uint16(data[currentPosition : currentPosition+2])
		recordClass := binary.BigEndian.Uint16(data[currentPosition+2 : currentPosition+4])
		ttl := binary.BigEndian.Uint32(data[currentPosition+4 : currentPosition+8])
		rdLength := binary.BigEndian.Uint16(data[currentPosition+8 : currentPosition+10])
		currentPosition += 10

		// 检查数据长度是否有效
		if currentPosition+int(rdLength) > len(data) {
			return nil, 0, fmt.Errorf("invalid record data length")
		}

		// 提取记录数据
		rdata := make([]byte, rdLength)
		copy(rdata, data[currentPosition:currentPosition+int(rdLength)])
		currentPosition += int(rdLength)

		records[i] = DNSRecord{
			Name:     name,
			Type:     recordType,
			Class:    recordClass,
			TTL:      ttl,
			RDLength: rdLength,
			rdata:    rdata,
		}
	}

	return records, currentPosition, nil
}

// 解析IP地址记录数据
func parseARecordData(rdata []byte) (string, error) {
	if len(rdata) != 4 {
		return "", fmt.Errorf("invalid A record data length")
	}
	// IPv4地址格式: 4字节，每个字节代表一个十进制数
	return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3]), nil
}

// 解析AAAA记录数据
func parseAAAARecordData(rdata []byte) (string, error) {
	if len(rdata) != 16 {
		return "", fmt.Errorf("invalid AAAA record data length")
	}
	// IPv6地址格式: 8个16位组，用冒号分隔
	ipv6Addr := make([]string, 8)
	for i := 0; i < 8; i++ {
		ipv6Addr[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(rdata[i*2:i*2+2]))
	}
	return strings.Join(ipv6Addr, ":"), nil
}

// 获取记录数据的可读表示
func getRecordDataString(record DNSRecord) string {
	// 根据记录类型解析数据
	switch record.Type {
	case 1: // A记录 (IPv4)
		ip, err := parseARecordData(record.rdata)
		if err == nil {
			return ip
		}
	case 28: // AAAA记录 (IPv6)
		ip, err := parseAAAARecordData(record.rdata)
		if err == nil {
			return ip
		}
	case 5: // CNAME记录
		// 解析CNAME数据
		cname, _, err := parseName(record.rdata, 0)
		if err == nil {
			return cname
		}
	case 2: // NS记录
		// 解析NS数据
		ns, _, err := parseName(record.rdata, 0)
		if err == nil {
			return ns
		}
	case 15: // MX记录
		// MX记录格式：优先级(2字节) + 邮件服务器域名
		priority := binary.BigEndian.Uint16(record.rdata[:2])
		server, _, err := parseName(record.rdata, 2)
		if err == nil {
			return fmt.Sprintf("%d %s", priority, server)
		}
	case 16: // TXT记录
		// TXT记录格式：长度字节 + 文本数据
		var txt strings.Builder
		pos := 0
		for pos < len(record.rdata) {
			length := int(record.rdata[pos])
			pos++
			if pos+length <= len(record.rdata) {
				txt.WriteString(string(record.rdata[pos : pos+length]))
				pos += length
			}
		}
		return txt.String()
	default:
		// 对于不支持的记录类型，返回十六进制表示
		return fmt.Sprintf("[%d bytes]", len(record.rdata))
	}
	// 如果解析失败，返回原始数据的十六进制表示
	return fmt.Sprintf("[%d bytes]", len(record.rdata))
}

// 解析DNS响应，提取更多信息
func parseDNSResponse(data []byte) (string, error) {
	header, _, err := parseDNSMessage(data)
	if err != nil {
		return "", err
	}

	// 获取响应码
	responseCode := getResponseCode(header.Flags)
	responseStr := responseCodeToString(responseCode)

	// 找到答案记录的起始位置
	position := 12
	for i := 0; i < int(header.QDCount); i++ {
		// 跳过域名
		_, newPosition, err2 := parseName(data, position)
		if err2 != nil {
			return responseStr, err2
		}
		position = newPosition + 4 // 跳过QType和QClass
	}

	// 解析答案记录
	answers, newPosition, err := parseDNSRecords(data, header.ANCount, position)
	if err != nil {
		// 如果解析失败，至少返回响应码信息
		responseStr += fmt.Sprintf(", ANSWERS: %d", header.ANCount)
		responseStr += fmt.Sprintf(", AUTHORITY: %d", header.NSCount)
		responseStr += fmt.Sprintf(", ADDITIONAL: %d", header.ARCount)
		return responseStr, nil
	}
	position = newPosition

	// 解析权威记录
	_, position, _ = parseDNSRecords(data, header.NSCount, position)

	// 解析附加记录
	_, _, _ = parseDNSRecords(data, header.ARCount, position)

	// 构建响应结果字符串
	responseStr += fmt.Sprintf(", ANSWERS: %d", len(answers))
	if len(answers) > 0 {
		responseStr += " ["
		for i, answer := range answers {
			recordTypeStr := recordTypeToString(answer.Type)
			dataStr := getRecordDataString(answer)
			responseStr += fmt.Sprintf("%s=%s", recordTypeStr, dataStr)
			if i < len(answers)-1 {
				responseStr += ", "
			}
		}
		responseStr += "]"
	}

	responseStr += fmt.Sprintf(", AUTHORITY: %d", header.NSCount)
	responseStr += fmt.Sprintf(", ADDITIONAL: %d", header.ARCount)

	return responseStr, nil
}

// 创建NXDomain响应
func createNXDomainResponse(queryData []byte) ([]byte, error) {
	// 复制原始查询数据作为响应的基础
	response := make([]byte, len(queryData))
	copy(response, queryData)

	// 设置响应标志：QR=1 (响应), RCODE=3 (NXDomain)
	flags := binary.BigEndian.Uint16(response[2:4])
	flags |= 0x8000  // 设置QR位为1
	flags &^= 0x000F // 清除RCODE
	flags |= 0x0003  // 设置RCODE为3 (NXDomain)
	binary.BigEndian.PutUint16(response[2:4], flags)

	// 保持其他字段不变
	return response, nil
}

// 解析域名
func parseName(data []byte, position int) (string, int, error) {
	var name strings.Builder
	currentPosition := position

	for {
		// 检查边界，确保currentPosition不超出data长度
		if currentPosition >= len(data) {
			return "", 0, fmt.Errorf("domain name parsing out of bounds")
		}
		length := int(data[currentPosition])
		currentPosition++

		if length == 0 {
			break
		}

		// 检查是否是指针
		if length&0xC0 == 0xC0 {
			// 指针格式: 前两位是11，后六位是偏移量的高六位
			// 下一个字节是偏移量的低八位
			// 检查边界，确保currentPosition不超出data长度
			if currentPosition >= len(data) {
				return "", 0, fmt.Errorf("invalid pointer in domain name")
			}
			pointer := int(((length & 0x3F) << 8) | int(data[currentPosition]))
			// 检查指针是否有效
			if pointer >= len(data) {
				return "", 0, fmt.Errorf("pointer points outside data")
			}
			pointerName, _, err := parseName(data, pointer)
			if err != nil {
				return "", 0, err
			}
			name.WriteString(pointerName)
			currentPosition++
			break
		} else if length <= 63 {
			// 普通标签
			if currentPosition+length > len(data) {
				return "", 0, fmt.Errorf("invalid domain name format")
			}
			name.WriteString(string(data[currentPosition : currentPosition+length]))
			currentPosition += length
			name.WriteString(".")
		} else {
			return "", 0, fmt.Errorf("invalid label length")
		}
	}

	// 移除末尾的点号
	result := name.String()
	if len(result) > 0 && result[len(result)-1] == '.' {
		result = result[:len(result)-1]
	}

	return result, currentPosition, nil
}

// 记录DNS查询日志
func logDNSQuery(clientIP string, header DNSHeader, questions []DNSQuestion, result string) {
	for _, question := range questions {
		logEntry := DNSLogEntry{
			Timestamp:     time.Now(),
			ClientIP:      clientIP,
			TransactionID: header.ID,
			DomainName:    question.Name,
			QueryType:     question.QType,
			QueryClass:    question.QClass,
			Result:        result,
		}

		logMutex.Lock()
		defer logMutex.Unlock()

		jsonData, err := json.Marshal(logEntry)
		if err != nil {
			log.Printf("Failed to marshal log entry: %v", err)
			return
		}

		_, err = logFile.Write(append(jsonData, '\n'))
		if err != nil {
			log.Printf("Failed to write to log file: %v", err)
		}
	}
}

// 处理UDP DNS请求
func handleUDPQuery(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	// 解析DNS请求
	header, questions, err := parseDNSMessage(data)
	if err != nil {
		log.Printf("Failed to parse DNS message: %v", err)
		return
	}

	// 域名过滤检查
	for _, question := range questions {
		domain := question.Name
		// 检查是否在白名单中
		if GetDomainFilter().IsInWhiteList(domain) {
			log.Printf("Domain %s in white list, allowing", domain)
			continue // 继续处理下一个问题
		}

		// 检查是否在封锁名单中
		if GetDomainFilter().IsBlocked(domain) {
			log.Printf("Domain %s is blocked, returning NXDOMAIN", domain)
			// 创建并发送NXDomain响应
			nxResponse, createErr := createNXDomainResponse(data)
			if createErr != nil {
				log.Printf("Failed to create NXDomain response: %v", createErr)
				return
			}

			// 发送NXDomain响应
			written, writeToUdpErr := conn.WriteToUDP(nxResponse, addr)
			if writeToUdpErr != nil || written != len(nxResponse) {
				log.Printf("Failed to send NXDomain response: %v", writeToUdpErr)
			}

			// 记录日志
			logDNSQuery(addr.IP.String(), header, questions, "BLOCKED: NXDOMAIN")
			return
		}
	}

	// 将请求转发到上游DNS服务器
	upstreamConn, err := net.Dial("udp", upstreamDNS)
	if err != nil {
		log.Printf("Failed to connect to upstream DNS: %v", err)
		logDNSQuery(addr.IP.String(), header, questions, "Failed to connect to upstream DNS")
		return
	}
	defer upstreamConn.Close()

	// 发送原始请求数据
	written, err := upstreamConn.Write(data)
	if err != nil || written != len(data) {
		log.Printf("Failed to send data to upstream DNS: %v", err)
		logDNSQuery(addr.IP.String(), header, questions, "Failed to send data to upstream DNS")
		return
	}

	// 设置读取超时
	err = upstreamConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Printf("Failed to set read deadline: %v", err)
		logDNSQuery(addr.IP.String(), header, questions, "Failed to set read deadline")
		return
	}

	// 读取上游DNS服务器的响应
	response := make([]byte, 512)
	responseLen, err := upstreamConn.Read(response)
	if err != nil {
		log.Printf("Failed to read response from upstream DNS: %v", err)
		logDNSQuery(addr.IP.String(), header, questions, "Failed to read response")
		return
	}

	// 将响应转发回客户端
	written, err = conn.WriteToUDP(response[:responseLen], addr)
	if err != nil || written != responseLen {
		log.Printf("Failed to send response to client: %v", err)
		logDNSQuery(addr.IP.String(), header, questions, "Failed to send response to client")
		return
	}

	// 解析并记录DNS响应结果
	responseResult, err := parseDNSResponse(response[:responseLen])
	if err != nil {
		log.Printf("Failed to parse DNS response: %v", err)
		responseResult = "Error parsing response"
	}
	logDNSQuery(addr.IP.String(), header, questions, responseResult)
}

// 处理TCP DNS请求
func handleTCPQuery(conn *net.TCPConn) {
	defer conn.Close()

	// 读取长度前缀(2字节)
	lengthBuf := make([]byte, 2)
	_, err := io.ReadFull(conn, lengthBuf)
	if err != nil {
		log.Printf("Failed to read DNS message length: %v", err)
		return
	}

	// 获取消息长度
	messageLength := binary.BigEndian.Uint16(lengthBuf)

	// 读取完整的DNS消息
	data := make([]byte, messageLength)
	_, err = io.ReadFull(conn, data)
	if err != nil {
		log.Printf("Failed to read DNS message: %v", err)
		return
	}

	// 解析DNS请求
	header, questions, err := parseDNSMessage(data)
	if err != nil {
		log.Printf("Failed to parse DNS message: %v", err)
		return
	}

	// 域名过滤检查
	for _, question := range questions {
		domain := question.Name
		// 检查是否在白名单中
		if GetDomainFilter().IsInWhiteList(domain) {
			log.Printf("Domain %s in white list, allowing", domain)
			continue // 继续处理下一个问题
		}

		// 检查是否在封锁名单中
		if GetDomainFilter().IsBlocked(domain) {
			log.Printf("Domain %s is blocked, returning NXDOMAIN", domain)
			// 创建并发送NXDomain响应
			nxResponse, createErr := createNXDomainResponse(data)
			if createErr != nil {
				log.Printf("Failed to create NXDomain response: %v", createErr)
				return
			}

			// 发送NXDomain响应（包含长度前缀）
			fullResponse := make([]byte, 2+len(nxResponse))
			binary.BigEndian.PutUint16(fullResponse[:2], uint16(len(nxResponse)))
			copy(fullResponse[2:], nxResponse)

			written, writeErr := conn.Write(fullResponse)
			if writeErr != nil || written != len(fullResponse) {
				log.Printf("Failed to send NXDomain response: %v", writeErr)
			}

			// 记录日志
			clientAddr := conn.RemoteAddr().(*net.TCPAddr)
			logDNSQuery(clientAddr.IP.String(), header, questions, "BLOCKED: NXDOMAIN")
			return
		}
	}

	// 将请求转发到上游DNS服务器
	upstreamConn, err := net.Dial("tcp", upstreamDNS)
	if err != nil {
		log.Printf("Failed to connect to upstream DNS: %v", err)
		clientAddr := conn.RemoteAddr().(*net.TCPAddr)
		logDNSQuery(clientAddr.IP.String(), header, questions, "Failed to connect to upstream DNS")
		return
	}
	defer upstreamConn.Close()

	// 发送原始请求数据(包含长度前缀)
	fullRequest := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(fullRequest[:2], uint16(len(data)))
	copy(fullRequest[2:], data)

	written, err := upstreamConn.Write(fullRequest)
	if err != nil || written != len(fullRequest) {
		log.Printf("Failed to send data to upstream DNS: %v", err)
		clientAddr := conn.RemoteAddr().(*net.TCPAddr)
		logDNSQuery(clientAddr.IP.String(), header, questions, "Failed to send data to upstream DNS")
		return
	}

	// 设置读取超时
	err = upstreamConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		log.Printf("Failed to set read deadline: %v", err)
		clientAddr := conn.RemoteAddr().(*net.TCPAddr)
		logDNSQuery(clientAddr.IP.String(), header, questions, "Failed to set read deadline")
		return
	}

	// 读取上游DNS服务器响应的长度前缀
	responseLengthBuf := make([]byte, 2)
	_, err = io.ReadFull(upstreamConn, responseLengthBuf)
	if err != nil {
		log.Printf("Failed to read response length: %v", err)
		clientAddr := conn.RemoteAddr().(*net.TCPAddr)
		logDNSQuery(clientAddr.IP.String(), header, questions, "Failed to read response length")
		return
	}

	// 获取响应消息长度
	responseMessageLength := binary.BigEndian.Uint16(responseLengthBuf)

	// 读取完整的响应消息
	response := make([]byte, responseMessageLength)
	_, err = io.ReadFull(upstreamConn, response)
	if err != nil {
		log.Printf("Failed to read response from upstream DNS: %v", err)
		clientAddr := conn.RemoteAddr().(*net.TCPAddr)
		logDNSQuery(clientAddr.IP.String(), header, questions, "Failed to read response")
		return
	}

	// 将响应转发回客户端(包含长度前缀)
	fullResponse := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(fullResponse[:2], uint16(len(response)))
	copy(fullResponse[2:], response)

	written, err = conn.Write(fullResponse)
	if err != nil || written != len(fullResponse) {
		log.Printf("Failed to send response to client: %v", err)
		clientAddr := conn.RemoteAddr().(*net.TCPAddr)
		logDNSQuery(clientAddr.IP.String(), header, questions, "Failed to send response to client")
		return
	}

	// 解析并记录DNS响应结果
	responseResult, err := parseDNSResponse(response)
	if err != nil {
		log.Printf("Failed to parse DNS response: %v", err)
		responseResult = "Error parsing response"
	}
	clientAddr := conn.RemoteAddr().(*net.TCPAddr)
	logDNSQuery(clientAddr.IP.String(), header, questions, responseResult)
}

func main() {
	// 初始化域名过滤器
	if err := InitDomainFilter("./env.toml"); err != nil {
		log.Printf("Warning: Failed to initialize domain filter: %v", err)
		// 创建一个空的过滤器继续运行
		filterOnce.Do(func() {
			domainFilter = &DomainFilter{
				blockedDomains:    make(map[string]struct{}),
				whiteListPatterns: make([]*regexp.Regexp, 0),
			}
		})
	}
	log.Printf("Domain filter initialized successfully")

	// 启动定时更新任务
	go StartDomainFilterUpdateTask("./env.toml")

	// 打开日志文件
	var err error
	logFile, err = os.OpenFile("dns_log.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	// 创建带缓冲的写入器
	writer := bufio.NewWriter(logFile)
	defer writer.Flush()

	// 启动UDP服务器
	udpAddr, err := net.ResolveUDPAddr("udp", ":53")
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to start UDP listener: %v", err)
	}
	defer udpConn.Close()

	log.Printf("DNS proxy listening on UDP port 53")

	// 启动TCP服务器
	tcpAddr, err := net.ResolveTCPAddr("tcp", ":53")
	if err != nil {
		log.Fatalf("Failed to resolve TCP address: %v", err)
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("Failed to start TCP listener: %v", err)
	}
	defer tcpListener.Close()

	log.Printf("DNS proxy listening on TCP port 53")

	// 启动协程处理TCP连接
	go func() {
		for {
			conn, err := tcpListener.AcceptTCP()
			if err != nil {
				log.Printf("Failed to accept TCP connection: %v", err)
				continue
			}
			go handleTCPQuery(conn)
		}
	}()

	// 处理UDP请求
	buffer := make([]byte, 512)
	for {
		n, addr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Failed to read from UDP: %v", err)
			continue
		}
		go handleUDPQuery(udpConn, addr, buffer[:n])
	}
}
