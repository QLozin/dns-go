package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	dnssrv "dnsgolang/app/src/dns"
	"dnsgolang/app/src/server/api"
	"dnsgolang/app/src/server/infra"
	"dnsgolang/app/src/server/service"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

func main() {
	// 设置环境变量，让子进程使用统一配置
	os.Setenv("DNSGO_DNS_ENV", "env.toml")
	os.Setenv("DNSGO_SERVER_ENV", "env.toml")

	// 加载配置
	cfg, err := dnssrv.LoadConfig("env.toml")
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 设置日志目录
	baseLogDir := ""
	if cfg != nil {
		baseLogDir = cfg.Log.Dir
	}

	// 创建独立的logger
	var dnsLogger *zap.Logger
	var serverLogger *zap.Logger

	if baseLogDir != "" {
		// 直接使用配置的日志目录，不创建子文件夹
		dnsLogger = dnssrv.NewLoggerWithFile(baseLogDir)
		serverLogger = dnssrv.NewLoggerWithFile(baseLogDir)
	} else {
		dnsLogger = dnssrv.NewDevelopmentLogger()
		serverLogger = dnssrv.NewDevelopmentLogger()
	}
	defer dnsLogger.Sync()
	defer serverLogger.Sync()

	// 打开数据库
	db, err := infra.Open("sqlite.sql")
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}

	// 创建服务
	var svc *service.Service
	if baseLogDir != "" {
		// 直接使用配置的日志目录，不创建子文件夹
		svc = service.NewWithLogDir(db, baseLogDir)
	} else {
		svc = service.NewWithLogger(db, serverLogger)
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		serverLogger.Info("收到停止信号，正在关闭服务器...")
		cancel()
	}()

	// 启动HTTP服务器
	e := echo.New()
	api.New(e, svc)
	e.Static("/", "app/web")
	httpErrCh := make(chan error, 1)
	go func() {
		serverLogger.Info("启动HTTP服务器", zap.String("端口", ":8080"))
		httpErrCh <- e.Start(":8080")
	}()

	// 启动DNS服务器
	dnsErrCh := make(chan error, 1)
	go func() {
		dnsLogger.Info("启动DNS服务器",
			zap.String("UDP监听", ":53"),
			zap.String("TCP监听", ":53"),
			zap.String("上游UDP", "100.90.80.129:5353"),
			zap.String("上游TCP", "100.90.80.129:5353"),
			zap.String("日志目录", baseLogDir))

		err := dnssrv.Start(ctx, dnssrv.Options{
			ListenUDP:    ":53",
			ListenTCP:    ":53",
			UpstreamUDP:  "100.90.80.129:5353",
			UpstreamTCP:  "100.90.80.129:5353",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			EnvPath:      "env.toml",
			Logger:       dnsLogger,
		}, svc.HandleDNSLog)
		dnsErrCh <- err
	}()

	// 等待任一服务器出错或收到停止信号
	select {
	case err := <-httpErrCh:
		if err != nil && err != http.ErrServerClosed {
			serverLogger.Fatal("HTTP服务器错误", zap.Error(err))
		}
	case err := <-dnsErrCh:
		if err != nil {
			dnsLogger.Fatal("DNS服务器错误", zap.Error(err))
		}
	}

	serverLogger.Info("服务器已停止")
}
