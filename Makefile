# DNS Golang 项目 Makefile

.PHONY: all dns server main clean test

# 默认目标
all: main

# 编译DNS服务器
dns:
	@echo "编译DNS服务器..."
	@cd app/src/dns && go build -o ../../_production/dns-server.exe .

# 编译HTTP服务器
server:
	@echo "编译HTTP服务器..."
	@cd app/src/server && go build -o ../../_production/http-server.exe .

# 编译主程序（统一运行）
main:
	@echo "编译主程序..."
	@go build -o _production/main.exe app/src/main.go

# 编译所有
build: dns server main

# 运行DNS服务器
run-dns: dns
	@echo "启动DNS服务器..."
	@echo "DNS日志将保存到: ./logs/dns-logs/"
	@cd app/src/dns && DNSGO_DNS_ENV=env.toml go run .

# 运行HTTP服务器
run-server: server
	@echo "启动HTTP服务器..."
	@echo "Server日志将保存到: ./logs/server-logs/"
	@cd app/src/server && DNSGO_SERVER_ENV=env.toml go run .

# 运行主程序
run-main: main
	@echo "启动主程序..."
	@echo "DNS日志将保存到: ./logs/dns-logs/"
	@echo "Server日志将保存到: ./logs/server-logs/"
	@./_production/main.exe

# 清理编译文件
clean:
	@echo "清理编译文件..."
	@rm -f _production/*.exe

# 运行测试
test:
	@echo "运行测试..."
	@go test ./...

# 安装依赖
deps:
	@echo "安装依赖..."
	@go mod download
	@go mod tidy

# 开发模式运行（带热重载）
dev:
	@echo "开发模式运行..."
	@go run app/src/main.go

# 帮助信息
help:
	@echo "可用命令:"
	@echo "  dns        - 编译DNS服务器"
	@echo "  server     - 编译HTTP服务器"
	@echo "  main       - 编译主程序"
	@echo "  build      - 编译所有程序"
	@echo "  run-dns    - 运行DNS服务器"
	@echo "  run-server - 运行HTTP服务器"
	@echo "  run-main   - 运行主程序"
	@echo "  clean      - 清理编译文件"
	@echo "  test       - 运行测试"
	@echo "  deps       - 安装依赖"
	@echo "  dev        - 开发模式运行"
	@echo "  help       - 显示帮助信息"
