package dns

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Block BlockConfig `toml:"block"`
	Log   LogConfig   `toml:"log"`
}

type BlockConfig struct {
	URLs      []string `toml:"urls"`
	WhiteList []string `toml:"white_list"`
	GeoIP2URL string   `toml:"geoip2_url"`
}

type LogConfig struct {
	Dir string `toml:"dir"`
}

func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); err != nil {
		return &Config{}, nil
	}
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
