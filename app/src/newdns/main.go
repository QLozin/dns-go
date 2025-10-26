package newdns

func main() {
	envPath := "./local.toml"
	cfg, err := LoadConfig(envPath)
	if err != nil {
		panic(err)
	}
}
