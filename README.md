# DNS代理服务器

这是一个使用Go语言编写的DNS代理服务器，它能够监听53端口，解析DNS请求，记录查询日志，并将请求转发到上游DNS服务器。

## 功能特点

- 同时支持UDP和TCP协议的DNS请求
- 解析DNS请求包，提取域名和查询信息
- 生成JSON格式的详细日志，记录查询时间、客户端IP、域名等信息
- **详细解析DNS响应结果**，包括响应码（如NOERROR、NXDOMAIN等）和具体的记录内容
- **支持解析多种DNS记录类型**：A（IPv4地址）、AAAA（IPv6地址）、CNAME、MX、NS、TXT等
- 将原始DNS请求转发到配置的上游DNS服务器
- 保持原始请求包和响应包不被修改
- 将上游DNS服务器的响应转发回客户端

## 配置

- 默认监听端口：53（UDP和TCP）
- 默认上游DNS服务器：`localhost:5353`
- 日志文件：`dns_log.json`

## 使用方法

1. 确保您有Go环境（推荐Go 1.16+）
2. 编译程序：
   ```
   go build -o dns_proxy main.go
   ```
3. 以管理员/root权限运行程序（因为需要监听53端口）：
   ```
   # Windows管理员权限
   .\dns_proxy.exe
   
   # Linux/Mac root权限
   sudo ./dns_proxy
   ```
4. 配置您的设备使用此DNS服务器

## 日志格式

日志以JSON格式保存在`dns_log.json`文件中，每条日志包含以下字段：

- `timestamp`：查询时间戳
- `client_ip`：客户端IP地址
- `transaction_id`：DNS事务ID
- `domain_name`：查询的域名
- `query_type`：查询类型（A记录、AAAA记录等）
- `query_class`：查询类（通常为IN，表示Internet）
- `result`：详细的查询结果，包括：
  - 响应码（如NOERROR、NXDOMAIN等）
  - 答案记录数量、权威记录数量、附加记录数量
  - 具体的答案记录内容（如IP地址、CNAME等）

## 注意事项

1. 运行此程序需要管理员/root权限，因为它需要监听53端口（特权端口）
2. 确保上游DNS服务器`localhost:5353`已配置并正常运行
3. 程序会自动创建日志文件，如果文件已存在则追加内容
4. 在生产环境中使用时，建议添加更多的错误处理和安全措施

## 上游DNS服务器配置

如果您需要修改上游DNS服务器，可以直接编辑`main.go`文件中的`upstreamDNS`变量。例如，要使用Google的公共DNS服务器：

```go
var (
    logFile    *os.File
    logMutex   sync.Mutex
    upstreamDNS = "8.8.8.8:53"
)
```

## 故障排除

- 如果程序无法启动，检查53端口是否已被其他程序占用
- 如果DNS查询失败，检查上游DNS服务器是否配置正确且可访问
- 查看程序输出的日志信息，了解详细的错误原因