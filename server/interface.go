package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
)

type Set map[string]*regexp.Regexp

type DnsLog struct {
	Time        string `json:"time"` // RFC3339Nano 格式，用于存储
	ClientIP    string `json:"client_ip"`
	UpstreamDNS string `json:"upstream_dns"`
	Protocol    string `json:"protocol"`
	QName       string `json:"qname"`
	QType       string `json:"qtype"`
	RCode       string `json:"rcode"`
	Answers     string `json:"answers"`
	Blocked     bool   `json:"blocked"`
	GeoCountry  string `json:"geo_country"`
	MsgId       int    `json:"msgId"`
	Error       string `json:"error"`
	RTT         string `json:"rtt"`
}

// 基础配置
type Config struct {
	ServerConfig ServerConfig `toml:"server"`
	BlockConfig  BlockConfig  `toml:"block"`
	Log          LogConfig    `toml:"log"`
	DB           DBConfig     `toml:"db"`
}

type ServerConfig struct {
	UdpPort      string        `toml:"udp_port"`
	UpstreamDNS  []string      `toml:"upstream_dns"`
	ReadTimeout  time.Duration `toml:"read_timeout"`
	WriteTimeout time.Duration `toml:"write_timeout"`
}

type BlockConfig struct {
	BlockDomains       []string `toml:"block_domains"`
	WhiteDomains       []string `toml:"white_domains"`
	WhiteIPs           []string `toml:"white_ips"`
	BlockIPs           []string `toml:"block_ips"`
	BlockSubscribeURLs []string `toml:"block_subscribe_urls"`
	GeoIP2URL          string   `toml:"geoip2_url"`
	RefreshHours       int      `toml:"refresh_hours"`
	Dir                string   `toml:"dir"`
}
type LogConfig struct {
	Dir        string `toml:"dir"`
	Level      string `toml:"level"`
	RotateDays int8   `toml:"rotate_days"`
	RotateSize int64  `toml:"rotate_size"`
}

type DBConfig struct {
	SqlitePath     string `toml:"sqlite_path"`
	MaxConnections int8   `toml:"max_connections"`
	Dir            string `toml:"dir"`
}

type DBOptions struct {
	DBConfig DBConfig
	Logger   *zap.Logger
}

type ServerOptions struct {
	ServerConfig ServerConfig
	BlockManager *Blocker
	Logger       *zap.Logger
	DB           *DB      // 使用新的 DB 类型替代 *sql.DB
	DevModes     []string // 开发模式列表：hook（forward时返回127.127.127.127）、trace（详细调试输出）
	LogOptions   []string // 日志选项列表：press（抑制未forward请求的控制台输出）
}

type BlockOptions struct {
	BlockConfig *BlockConfig
	Logger      *zap.Logger
}

// 服务配置
type Server struct {
	*ServerOptions
	stopCh      chan struct{}
	ctx         context.Context
	upstreamDNS []net.UDPAddr
}

type Blocker struct {
	*BlockOptions
	mutexes         BlockerMutex
	domainSet       Set
	whiteDomainSet  Set
	whiteIPSet      *IPSet
	blockIPSet      *IPSet
	localIPSet      *IPSet
	stopCh          chan struct{}
	ctx             context.Context
	geoDB           atomic.Pointer[geoip2.Reader]
	GeoReady        atomic.Bool
	DomainListReady atomic.Bool
}

type BlockerMutex struct {
	domainSet      sync.RWMutex
	whiteDomainSet sync.RWMutex
}

func LoadConfig(path string) (*Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	return &cfg, nil
}

func WithServerConfig(cfg ServerConfig) func(opts_ *ServerOptions) {
	return func(opts_ *ServerOptions) {
		opts_.ServerConfig = cfg
	}
}
func WithLogger(logger *zap.Logger) func(opts_ *ServerOptions) {
	return func(opts_ *ServerOptions) {
		opts_.Logger = logger
	}
}
func WithBlockManager(blockManager *Blocker) func(opts_ *ServerOptions) {
	return func(opts_ *ServerOptions) {
		opts_.BlockManager = blockManager
	}
}
func WithDB(db *DB) func(opts_ *ServerOptions) {
	return func(opts_ *ServerOptions) {
		opts_.DB = db
	}
}

func WithBlockConfig(cfg BlockConfig) func(opts_ *BlockOptions) {
	return func(opts_ *BlockOptions) {
		opts_.BlockConfig = &cfg
	}
}

func WithDBConfig(logger *zap.Logger) func(opts_ *DBOptions) {
	return func(opts_ *DBOptions) {
		opts_.Logger = logger
	}
}

func WithDevModes(devModes []string) func(opts_ *ServerOptions) {
	return func(opts_ *ServerOptions) {
		opts_.DevModes = devModes
	}
}

func WithLogOptions(logOptions []string) func(opts_ *ServerOptions) {
	return func(opts_ *ServerOptions) {
		opts_.LogOptions = logOptions
	}
}
