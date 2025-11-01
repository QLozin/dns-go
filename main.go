package main

import (
	"context"
	"dnsgolang/server"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	configPath = flag.String("config", "default.toml", "配置文件路径")
	devMode    = flag.String("dev", "", "开发模式（可用逗号分隔多个）: hook（forward时返回127.127.127.127）、trace（详细调试输出）")
	logOptions = flag.String("log-options", "", "日志选项（可用逗号分隔多个）: press（抑制未forward请求的控制台输出）")
	version    = "1.0.0"
)

// NewLoggerWithFile 创建带文件输出的logger（JSON格式，支持轮转）
func NewLoggerWithFile(logDir string, level string) (*zap.Logger, error) {
	// 创建日志目录
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("创建日志目录失败: %w", err)
		}
	}

	// 解析日志级别
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zap.InfoLevel
	}

	// 配置编码器
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.LevelKey = "level"
	encoderConfig.MessageKey = "message"
	encoderConfig.CallerKey = "caller"
	encoderConfig.StacktraceKey = "stacktrace"

	// 创建文件写入器（支持轮转）
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   filepath.Join(logDir, "dns.log"),
		MaxSize:    16,   // 16MB
		MaxBackups: 3,    // 保留3个备份
		MaxAge:     30,   // 保留30天
		Compress:   true, // 压缩旧文件
	})

	// 控制台写入器
	consoleWriter := zapcore.AddSync(os.Stdout)

	// 创建核心
	var cores []zapcore.Core

	// 文件核心（JSON格式）
	if fileWriter != nil {
		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			fileWriter,
			zapLevel,
		)
		cores = append(cores, fileCore)
	}

	// 控制台核心（开发格式）
	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		consoleWriter,
		zap.DebugLevel, // 控制台总是显示debug级别
	)
	cores = append(cores, consoleCore)

	// 合并核心
	core := zapcore.NewTee(cores...)

	// 创建logger
	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel)), nil
}

func main() {
	flag.Parse()

	// 设置 GO_RWMUTEX_WRITESTARVATION 环境变量为 1，启用写锁优先模式，避免写锁饥饿
	if os.Getenv("GO_RWMUTEX_WRITESTARVATION") == "" {
		os.Setenv("GO_RWMUTEX_WRITESTARVATION", "1")
	}

	// 读取配置文件
	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		fmt.Printf("加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	// 确保日志目录存在
	if cfg.Log.Dir == "" {
		cfg.Log.Dir = "./logs"
	}
	if err := os.MkdirAll(cfg.Log.Dir, 0755); err != nil {
		fmt.Printf("创建日志目录失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化logger
	logger, err := NewLoggerWithFile(cfg.Log.Dir, cfg.Log.Level)
	if err != nil {
		fmt.Printf("初始化日志失败: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("DNS服务器启动", zap.String("版本", version), zap.String("配置文件", *configPath))

	// 创建上下文和信号通道
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 确保数据库目录存在
	if cfg.DB.Dir == "" {
		cfg.DB.Dir = "./data"
	}
	if err := os.MkdirAll(cfg.DB.Dir, 0755); err != nil {
		logger.Fatal("创建数据库目录失败", zap.Error(err))
	}

	// 如果sqlite_path是相对路径，则基于dir目录
	if !filepath.IsAbs(cfg.DB.SqlitePath) && cfg.DB.Dir != "" {
		cfg.DB.SqlitePath = filepath.Join(cfg.DB.Dir, filepath.Base(cfg.DB.SqlitePath))
	}

	// 初始化数据库
	dbOptions := &server.DBOptions{
		DBConfig: cfg.DB,
		Logger:   logger,
	}
	db, err := server.NewDB(dbOptions)
	if err != nil {
		logger.Fatal("初始化数据库失败", zap.Error(err))
	}
	defer db.Close()

	logger.Info("数据库初始化完成", zap.String("路径", cfg.DB.SqlitePath))

	// 确保Block工作目录存在
	if cfg.BlockConfig.Dir == "" {
		cfg.BlockConfig.Dir = "./block"
	}
	if err := os.MkdirAll(cfg.BlockConfig.Dir, 0755); err != nil {
		logger.Fatal("创建Block工作目录失败", zap.Error(err))
	}

	// 初始化Blocker
	blockOptions := []func(*server.BlockOptions){
		server.WithBlockConfig(cfg.BlockConfig),
		func(opts *server.BlockOptions) {
			opts.Logger = logger
		},
	}
	blocker := server.NewBlockManager(ctx, blockOptions...)

	// 启动Blocker（异步）
	blockerErrCh := make(chan error, 1)
	go func() {
		if err := blocker.Start(); err != nil {
			logger.Error("Blocker启动失败", zap.Error(err))
			blockerErrCh <- err
		}
	}()

	// 等待Blocker初始化完成
	timeout := 60 * time.Second
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	logger.Info("等待Blocker初始化完成...")
	for {
		if blocker.GeoReady.Load() && blocker.DomainListReady.Load() {
			logger.Info("Blocker初始化完成")
			break
		}
		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				logger.Fatal("Blocker初始化超时")
			}
		case err := <-blockerErrCh:
			logger.Fatal("Blocker启动失败", zap.Error(err))
		case <-ctx.Done():
			logger.Info("接收到停止信号，退出")
			return
		}
	}

	// 解析dev模式（支持逗号分隔的多个值）
	var devModes []string
	if *devMode != "" {
		modes := strings.Split(*devMode, ",")
		for _, m := range modes {
			m = strings.TrimSpace(m)
			if m != "" {
				devModes = append(devModes, m)
			}
		}
		if len(devModes) > 0 {
			logger.Info("开发模式已启用", zap.Strings("模式", devModes))
		}
	}

	// 解析log选项（支持逗号分隔的多个值）
	var logOpts []string
	if *logOptions != "" {
		opts := strings.Split(*logOptions, ",")
		for _, opt := range opts {
			opt = strings.TrimSpace(opt)
			if opt != "" {
				logOpts = append(logOpts, opt)
			}
		}
		if len(logOpts) > 0 {
			logger.Info("日志选项已启用", zap.Strings("选项", logOpts))
		}
	}

	// 初始化Server
	serverOptions := []func(*server.ServerOptions){
		server.WithServerConfig(cfg.ServerConfig),
		server.WithLogger(logger),
		server.WithBlockManager(blocker),
		server.WithDB(db),
	}
	if len(devModes) > 0 {
		serverOptions = append(serverOptions, server.WithDevModes(devModes))
	}
	if len(logOpts) > 0 {
		serverOptions = append(serverOptions, server.WithLogOptions(logOpts))
	}
	dnsServer := server.NewServer(ctx, serverOptions...)

	// 启动Server（异步）
	serverErrCh := make(chan error, 1)
	go func() {
		if err := dnsServer.Start(); err != nil {
			logger.Error("Server启动失败", zap.Error(err))
			serverErrCh <- err
		}
	}()

	logger.Info("DNS服务器启动成功",
		zap.String("UDP端口", cfg.ServerConfig.UdpPort),
		zap.Strings("上游DNS", cfg.ServerConfig.UpstreamDNS),
	)

	// 等待停止信号或错误
	select {
	case sig := <-sigCh:
		logger.Info("接收到停止信号", zap.String("信号", sig.String()))
		cancel()
		dnsServer.Stop()
		blocker.Stop()
	case err := <-serverErrCh:
		logger.Error("Server发生错误", zap.Error(err))
		cancel()
		blocker.Stop()
	case err := <-blockerErrCh:
		logger.Error("Blocker发生错误", zap.Error(err))
		cancel()
		dnsServer.Stop()
	case <-ctx.Done():
		logger.Info("上下文取消")
	}

	// 等待服务关闭
	time.Sleep(5 * time.Second)
	logger.Info("DNS服务器已停止")
}
