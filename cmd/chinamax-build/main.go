package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type sourceFile struct {
	Payload []string `yaml:"payload"`
}

type compact struct {
	Source      string     `json:"source"`
	GeneratedAt string     `json:"generatedAt"`
	Stats       buildStats `json:"stats"`
	Exacts      []string   `json:"exacts"`
	Suffixes    []string   `json:"suffixes"`
	Keywords    []string   `json:"keywords"`
	CIDRv4      []string   `json:"cidr_v4"`
	CIDRv6      []string   `json:"cidr_v6"`
}

type buildStats struct {
	Exacts   int `json:"exacts"`
	Suffixes int `json:"suffixes"`
	Keywords int `json:"keywords"`
	CIDRv4   int `json:"cidr_v4"`
	CIDRv6   int `json:"cidr_v6"`
	Skipped  int `json:"skipped"`
}

func main() {
	src := flag.String("src", "./vendor/ChinaMax_Classical.yaml", "path to ChinaMax_Classical.yaml")
	out := flag.String("out", "./data/chinamax_classical.compact.json", "output file")
	includePath := flag.String("include", "./data/local-include.txt", "local include file")
	excludePath := flag.String("exclude", "./data/local-exclude.txt", "local exclude file")
	flag.Parse()

	data, err := os.ReadFile(*src)
	if err != nil {
		panic(err)
	}
	var sf sourceFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		panic(err)
	}

	b := builder{
		exacts:   map[string]struct{}{},
		suffixes: map[string]struct{}{},
		keywords: map[string]struct{}{},
		cidr4:    map[string]struct{}{},
		cidr6:    map[string]struct{}{},
	}
	for _, line := range sf.Payload {
		b.consume(line)
	}
	if err := applyLocalFile(*includePath, &b, false); err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	if err := applyLocalFile(*excludePath, &b, true); err != nil && !os.IsNotExist(err) {
		panic(err)
	}

	payload := compact{
		Source:      *src,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Stats: buildStats{
			Exacts: len(b.exacts), Suffixes: len(b.suffixes), Keywords: len(b.keywords), CIDRv4: len(b.cidr4), CIDRv6: len(b.cidr6), Skipped: b.skipped,
		},
		Exacts:   sortedKeys(b.exacts),
		Suffixes: sortedKeys(b.suffixes),
		Keywords: sortedKeys(b.keywords),
		CIDRv4:   sortedKeys(b.cidr4),
		CIDRv6:   sortedKeys(b.cidr6),
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		panic(err)
	}
	outBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*out, outBytes, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("[ok] wrote %s\n", *out)
	fmt.Printf("[ok] exacts=%d suffixes=%d keywords=%d cidr4=%d cidr6=%d skipped=%d\n", len(payload.Exacts), len(payload.Suffixes), len(payload.Keywords), len(payload.CIDRv4), len(payload.CIDRv6), payload.Stats.Skipped)
}

type builder struct {
	exacts, suffixes, keywords, cidr4, cidr6 map[string]struct{}
	skipped                                  int
}

func (b *builder) consume(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		b.skipped++
		return
	}
	typ := strings.ToUpper(strings.TrimSpace(parts[0]))
	val := strings.TrimSpace(parts[1])
	switch typ {
	case "DOMAIN":
		b.exacts[normalizeDomain(val)] = struct{}{}
	case "DOMAIN-SUFFIX":
		b.suffixes[normalizeDomain(val)] = struct{}{}
	case "DOMAIN-KEYWORD":
		b.keywords[strings.ToLower(strings.TrimSpace(val))] = struct{}{}
	case "IP-CIDR":
		b.cidr4[strings.TrimSpace(val)] = struct{}{}
	case "IP-CIDR6":
		b.cidr6[strings.TrimSpace(val)] = struct{}{}
	default:
		b.skipped++
	}
}

func applyLocalFile(path string, b *builder, remove bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(strings.ToLower(line), "domain:"):
			put(b.exacts, normalizeDomain(line[len("domain:"):]), remove)
		case strings.HasPrefix(strings.ToLower(line), "domain-suffix:"):
			put(b.suffixes, normalizeDomain(line[len("domain-suffix:"):]), remove)
		case strings.HasPrefix(strings.ToLower(line), "domain-keyword:"):
			put(b.keywords, strings.ToLower(strings.TrimSpace(line[len("domain-keyword:"):])), remove)
		case strings.HasPrefix(strings.ToLower(line), "ip-cidr:"):
			put(b.cidr4, strings.TrimSpace(line[len("ip-cidr:"):]), remove)
		case strings.HasPrefix(strings.ToLower(line), "ip-cidr6:"):
			put(b.cidr6, strings.TrimSpace(line[len("ip-cidr6:"):]), remove)
		default:
			put(b.suffixes, normalizeDomain(line), remove)
		}
	}
	return sc.Err()
}

func put(m map[string]struct{}, v string, remove bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if remove {
		delete(m, v)
	} else {
		m[v] = struct{}{}
	}
}

func normalizeDomain(v string) string {
	return strings.Trim(strings.TrimSpace(strings.ToLower(v)), ".")
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
