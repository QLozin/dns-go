package toml

import (
	"bufio"
	"os"
	"reflect"
	"strings"
)

// MetaData is a stub to match the BurntSushi/toml API surface we use.
type MetaData struct{}

// DecodeFile is a very small, limited TOML decoder sufficient for this project's config.
// It supports a single [block] table with string array keys: urls, white_list.
func DecodeFile(path string, v any) (MetaData, error) {
	f, err := os.Open(path)
	if err != nil {
		return MetaData{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inBlock := false
	var urls []string
	var whitelist []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.Trim(line, "[]")
			inBlock = name == "block"
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasPrefix(line, "urls=") {
			urls = parseStringArray(line[len("urls="):])
			continue
		}
		if strings.HasPrefix(line, "white_list=") {
			whitelist = parseStringArray(line[len("white_list="):])
			continue
		}
	}

	// Populate into struct via reflection: expect struct with field Block containing URLs and WhiteList.
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return MetaData{}, nil
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return MetaData{}, nil
	}
	blockField := rv.FieldByName("Block")
	if blockField.IsValid() && blockField.CanSet() && blockField.Kind() == reflect.Struct {
		// URLs
		urlsField := blockField.FieldByName("URLs")
		if urlsField.IsValid() && urlsField.CanSet() && urlsField.Kind() == reflect.Slice {
			urlsVals := reflect.MakeSlice(urlsField.Type(), 0, len(urls))
			for _, s := range urls {
				urlsVals = reflect.Append(urlsVals, reflect.ValueOf(s))
			}
			urlsField.Set(urlsVals)
		}
		wlField := blockField.FieldByName("WhiteList")
		if wlField.IsValid() && wlField.CanSet() && wlField.Kind() == reflect.Slice {
			wlVals := reflect.MakeSlice(wlField.Type(), 0, len(whitelist))
			for _, s := range whitelist {
				wlVals = reflect.Append(wlVals, reflect.ValueOf(s))
			}
			wlField.Set(wlVals)
		}
		rv.FieldByName("Block").Set(blockField)
	}
	return MetaData{}, scanner.Err()
}

func parseStringArray(raw string) []string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return nil
	}
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	parts := splitCSV(raw)
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "\"")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitCSV(s string) []string {
	var res []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQ = !inQ
			cur.WriteByte(c)
			continue
		}
		if c == ',' && !inQ {
			res = append(res, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		res = append(res, cur.String())
	}
	return res
}
