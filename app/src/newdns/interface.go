package newdns

import (
	"context"
	"database/sql"
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
	Time        string `json:"time"`
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
	UpstreamDNS  string        `toml:"upstream_dns"`
	ReadTimeout  time.Duration `toml:"read_timeout"`
	WriteTimeout time.Duration `toml:"write_timeout"`
}

type BlockConfig struct {
	BlockDomains       []string `toml:"block_domains"`
	WhiteDomains       []string `toml:"white_domains"`
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

type ServerOptions struct {
	ServerConfig ServerConfig
	BlockManager *Blocker
	Logger       *zap.Logger
	DB           *sql.DB
}

type BlockOptions struct {
	BlockConfig *BlockConfig
	Logger      *zap.Logger
}

// 服务配置
type Server struct {
	*ServerOptions
	stopCh         chan struct{}
	ctx            context.Context
	blockerManager *Blocker
}

type Blocker struct {
	*BlockOptions
	mutexes         BlockerMutex
	domainSet       Set
	whiteDomainSet  Set
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
	if _, err := toml.Decode(path, &cfg); err != nil {
		return nil, err
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
func WithDB(db *sql.DB) func(opts_ *ServerOptions) {
	return func(opts_ *ServerOptions) {
		opts_.DB = db
	}
}

func WithBlockConfig(cfg BlockConfig) func(opts_ *BlockOptions) {
	return func(opts_ *BlockOptions) {
		opts_.BlockConfig = &cfg
	}
}
