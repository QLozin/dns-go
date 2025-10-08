package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"dnsgolang/app/src/server/api"
	"dnsgolang/app/src/server/infra"
	"dnsgolang/app/src/server/service"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

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
			Filename:   logDir + "/server.log",
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

func main() {
	// 从环境变量获取配置路径
	envPath := os.Getenv("DNSGO_SERVER_ENV")
	if envPath == "" {
		envPath = "env.toml" // 默认配置
	}

	// 设置日志目录，Server子系统以server-开头
	logDir := "./logs/server-logs"

	// 创建Server子系统专用的logger（文件+控制台）
	logger := NewLoggerWithFile(logDir)
	defer logger.Sync()

	// 打开数据库
	db, err := infra.Open("sqlite.sql")
	if err != nil {
		logger.Fatal("打开数据库失败", zap.Error(err))
	}

	// 创建服务
	svc := service.NewWithLogDir(db, logDir)

	// 创建HTTP服务器
	e := echo.New()

	// 添加CORS中间件
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("Access-Control-Allow-Origin", "*")
			c.Response().Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Response().Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			return next(c)
		}
	})

	api.New(e, svc)

	// 提供静态web文件
	e.Static("/", "app/web")

	// 设置信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("收到停止信号，正在关闭HTTP服务器...")
		if err := e.Shutdown(context.Background()); err != nil {
			logger.Error("关闭HTTP服务器失败", zap.Error(err))
		}
	}()

	// 启动HTTP服务器
	logger.Info("启动HTTP服务器", zap.String("端口", ":8080"))

	if err := e.Start(":8080"); err != nil && err != http.ErrServerClosed {
		logger.Fatal("HTTP服务器启动失败", zap.Error(err))
	}

	logger.Info("HTTP服务器已停止")
}
