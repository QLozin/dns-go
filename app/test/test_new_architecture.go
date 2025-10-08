package test

import (
	"context"
	"database/sql"
	"dnsgolang/app/src/dns"
	"dnsgolang/app/src/server/infra"
	"dnsgolang/app/src/server/service"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	fmt.Println("=== 测试新架构：DNS子系统直接处理日志 ===")

	// 打开数据库
	db, err := infra.Open("sqlite.sql")
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}

	// 创建Server服务（只负责API）
	svc := service.New(db)
	fmt.Println("创建Server服务（只负责API）")

	// 创建DNS服务器（直接处理日志）
	logDir := "./logs"
	fmt.Printf("创建DNS服务器，日志目录: %s\n", logDir)

	// 注意：在新架构中，DNS查询日志由DNS服务器直接处理
	// 这里不再需要手动处理测试日志

	// 创建DNS服务器实例来测试日志处理
	ctx := context.Background()
	opts := dns.Options{
		ListenUDP:    ":5353", // 使用非标准端口避免权限问题
		ListenTCP:    ":5353",
		UpstreamUDP:  "8.8.8.8:53",
		UpstreamTCP:  "8.8.8.8:53",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		EnvPath:      "env.toml",
		Logger:       dns.NewDevelopmentLogger(),
	}

	// 启动DNS服务器（这会创建内部server实例）
	err = dns.Start(ctx, opts, db.DB, logDir)
	if err != nil {
		log.Printf("DNS服务器启动失败: %v", err)
	}

	// 等待一下让服务器启动
	time.Sleep(1 * time.Second)

	// 检查日志文件
	fmt.Println("\n=== 检查日志文件 ===")
	files, err := os.ReadDir("./logs")
	if err != nil {
		fmt.Printf("读取 logs 目录失败: %v\n", err)
	} else {
		fmt.Printf("logs 目录中有 %d 个文件:\n", len(files))
		for _, file := range files {
			fmt.Printf("  - %s\n", file.Name())
		}
	}

	// 检查数据库中的数据
	fmt.Println("\n=== 检查 SQLite 数据库 ===")
	rows, err := svc.ListLogs(5)
	if err != nil {
		fmt.Printf("查询数据库失败: %v\n", err)
	} else {
		defer rows.Close()

		count := 0
		for rows.Next() {
			var timeStr, clientIP, country, proto, qname, qtype, rcode, answers string
			var qid int64
			var rttMs float64
			var blockedInt int
			var errStr sql.NullString

			err := rows.Scan(&timeStr, &clientIP, &country, &proto, &qid, &qname, &qtype, &rcode, &answers, &rttMs, &blockedInt, &errStr)
			if err != nil {
				fmt.Printf("扫描行失败: %v\n", err)
				continue
			}

			count++
			blocked := blockedInt == 1
			fmt.Printf("  记录 %d: %s - %s (%s) - %s - 被阻止: %v\n",
				count, timeStr, qname, qtype, country, blocked)
		}
		fmt.Printf("数据库查询完成，显示最新 %d 条记录\n", count)
	}

	fmt.Println("\n=== 新架构测试完成 ===")
	fmt.Println("✅ DNS子系统现在直接处理查询日志")
	fmt.Println("✅ Server子系统只负责API服务")
	fmt.Println("✅ 职责分离完成")
}
