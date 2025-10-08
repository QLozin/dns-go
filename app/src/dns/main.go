package dns

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	// 从环境变量获取配置路径
	envPath := os.Getenv("DNSGO_DNS_ENV")
	if envPath == "" {
		envPath = "env.toml" // 默认配置
	}

	// 加载配置
	cfg, err := LoadConfig(envPath)
	if err != nil {
		// 如果配置加载失败，使用默认logger
		logger := NewDevelopmentLogger()
		logger.Fatal("加载配置失败", zap.Error(err))
		os.Exit(1)
	}

	// 设置日志目录，DNS子系统直接使用配置目录，不创建子文件夹
	logDir := ""
	if cfg != nil && cfg.Log.Dir != "" {
		logDir = cfg.Log.Dir
	}

	// 创建DNS子系统专用的logger（文件+控制台）
	logger := NewLoggerWithFile(logDir)
	defer logger.Sync()

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("收到停止信号，正在关闭DNS服务器...")
		cancel()
	}()

	// 启动DNS服务器
	logger.Info("启动DNS服务器",
		zap.String("UDP监听", ":53"),
		zap.String("TCP监听", ":53"),
		zap.String("上游UDP", "100.90.80.129:5353"),
		zap.String("上游TCP", "100.90.80.129:5353"),
		zap.String("日志目录", logDir))

	err = Start(ctx, Options{
		ListenUDP:    ":53",
		ListenTCP:    ":53",
		UpstreamUDP:  "100.90.80.129:5353",
		UpstreamTCP:  "100.90.80.129:5353",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		EnvPath:      "env.toml",
		Logger:       logger,
	}, func(logObj DnsLogObj) {
		// DNS日志处理函数
		logger.Info("DNS查询",
			zap.String("客户端IP", logObj.ClientIP),
			zap.String("国家", logObj.CountryZH),
			zap.String("协议", logObj.Protocol),
			zap.String("查询域名", logObj.QName),
			zap.String("查询类型", logObj.QType),
			zap.String("响应码", logObj.RCode),
			zap.String("响应时间", logObj.RTT),
			zap.Bool("被阻止", logObj.Blocked),
			zap.String("错误", logObj.Error),
		)
	})

	if err != nil {
		logger.Fatal("DNS服务器启动失败", zap.Error(err))
	}

	logger.Info("DNS服务器已停止")
}

// NewLogger 创建DNS子系统专用的logger
func NewLogger() *zap.Logger {
	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.CallerKey = "caller"
	config.EncoderConfig.StacktraceKey = "stacktrace"

	logger, _ := config.Build()
	return logger
}

// NewDevelopmentLogger 创建开发环境用的logger
func NewDevelopmentLogger() *zap.Logger {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, _ := config.Build()
	return logger
}

// NewLoggerWithFile 创建带文件输出的logger（JSON格式，支持轮转）
func NewLoggerWithFile(logDir string) *zap.Logger {
	// 创建日志目录
	if logDir != "" {
		os.MkdirAll(logDir, 0755)
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
	var fileWriter zapcore.WriteSyncer
	if logDir != "" {
		fileWriter = zapcore.AddSync(&lumberjack.Logger{
			Filename:   logDir + "/dns-2006-01-02T15-04-05.json",
			MaxSize:    5,    // 5MB
			MaxBackups: 3,    // 保留3个备份
			MaxAge:     3,    // 保留3天
			Compress:   true, // 压缩旧文件
		})
	}

	// 控制台写入器
	consoleWriter := zapcore.AddSync(os.Stdout)

	// 创建核心
	var cores []zapcore.Core

	// 文件核心（JSON格式）
	if fileWriter != nil {
		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			fileWriter,
			zap.InfoLevel,
		)
		cores = append(cores, fileCore)
	}

	// 控制台核心（开发格式）
	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		consoleWriter,
		zap.DebugLevel,
	)
	cores = append(cores, consoleCore)

	// 合并核心
	core := zapcore.NewTee(cores...)

	// 创建logger
	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
}
