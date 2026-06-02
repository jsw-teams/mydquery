package config

import (
	"fmt"
	"os"
	"time"

	"gateway-dquery-go/internal/account"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig            `yaml:"server"`
	Logging    LoggingConfig           `yaml:"logging"`
	ChinaRules ChinaRulesConfig        `yaml:"china_rules"`
	Routing    RoutingConfig           `yaml:"routing"`
	ECS        ECSConfig               `yaml:"ecs"`
	Cache      CacheConfig             `yaml:"cache"`
	CNLearning CNLearningConfig        `yaml:"cn_learning"`
	Account    account.Config          `yaml:"account"`
	Storage    StorageConfig           `yaml:"storage"`
	Upstreams  map[string]UpstreamSpec `yaml:"upstreams"`
}

type ServerConfig struct {
	Listen         string        `yaml:"listen"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	MaxRequestBody int64         `yaml:"max_request_body"`
	ClientIPHeader string        `yaml:"client_ip_header"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

type ChinaRulesConfig struct {
	CompactJSONPath string `yaml:"compact_json_path"`
}

type RoutingConfig struct {
	CN                   RouteConfig `yaml:"cn"`
	Global               RouteConfig `yaml:"global"`
	DebugResponseHeaders bool        `yaml:"debug_response_headers"`
}

type RouteConfig struct {
	Upstream         string `yaml:"upstream"`
	FallbackUpstream string `yaml:"fallback_upstream"`
	ECSSource        string `yaml:"ecs_source"`
}

type ECSConfig struct {
	VisitorV4Mask  int    `yaml:"visitor_v4_mask"`
	VisitorV6Mask  int    `yaml:"visitor_v6_mask"`
	ClientV4Max    int    `yaml:"client_v4_max_mask"`
	ClientV6Max    int    `yaml:"client_v6_max_mask"`
	AllowQueryECS  bool   `yaml:"allow_query_ecs"`
	AllowHeaderECS bool   `yaml:"allow_header_ecs"`
	HeaderName     string `yaml:"header_name"`
}

type CacheConfig struct {
	Enabled                      bool          `yaml:"enabled"`
	MaxItems                     int           `yaml:"max_items"`
	DefaultPositiveTTL           time.Duration `yaml:"default_positive_ttl"`
	MinPositiveTTL               time.Duration `yaml:"min_positive_ttl"`
	MaxPositiveTTL               time.Duration `yaml:"max_positive_ttl"`
	NegativeTTL                  time.Duration `yaml:"negative_ttl"`
	StaleIfError                 time.Duration `yaml:"stale_if_error"`
	ResponseBrowserMaxAge        time.Duration `yaml:"response_browser_max_age"`
	ResponseSharedMaxAge         time.Duration `yaml:"response_shared_max_age"`
	ResponseStaleWhileRevalidate time.Duration `yaml:"response_stale_while_revalidate"`
	ResponseStaleIfError         time.Duration `yaml:"response_stale_if_error"`
}

type CNLearningConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Mode     string        `yaml:"mode"`
	TTLCap   time.Duration `yaml:"ttl_cap"`
	TTLFloor time.Duration `yaml:"ttl_floor"`
}

type StorageConfig struct {
	DBPath string `yaml:"db_path"`
}

type UpstreamSpec struct {
	Type          string            `yaml:"type"`
	URL           string            `yaml:"url"`
	Method        string            `yaml:"method"`
	Timeout       time.Duration     `yaml:"timeout"`
	Headers       map[string]string `yaml:"headers"`
	HTTPVersion   string            `yaml:"http_version"`
	OutboundProxy string            `yaml:"outbound_proxy"`
	MaxConcurrent int               `yaml:"max_concurrent"`
	HMAC          UpstreamHMACSpec  `yaml:"hmac"`
}

type UpstreamHMACSpec struct {
	Enabled   bool   `yaml:"enabled"`
	KeyID     string `yaml:"key_id"`
	Secret    string `yaml:"secret"`
	SecretEnv string `yaml:"secret_env"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:18053"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 10 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 20 * time.Second
	}
	if c.Server.IdleTimeout == 0 {
		c.Server.IdleTimeout = 60 * time.Second
	}
	if c.Server.MaxRequestBody == 0 {
		c.Server.MaxRequestBody = 65535
	}
	if c.Server.ClientIPHeader == "" {
		c.Server.ClientIPHeader = "CF-Connecting-IP"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.ECS.VisitorV4Mask == 0 {
		c.ECS.VisitorV4Mask = 24
	}
	if c.ECS.VisitorV6Mask == 0 {
		c.ECS.VisitorV6Mask = 48
	}
	if c.ECS.ClientV4Max == 0 {
		c.ECS.ClientV4Max = 24
	}
	if c.ECS.ClientV6Max == 0 {
		c.ECS.ClientV6Max = 48
	}
	if c.ECS.HeaderName == "" {
		c.ECS.HeaderName = "X-ECS"
	}
	if c.Cache.MaxItems == 0 {
		c.Cache.MaxItems = 20000
	}
	if c.Cache.DefaultPositiveTTL == 0 {
		c.Cache.DefaultPositiveTTL = 120 * time.Second
	}
	if c.Cache.MinPositiveTTL == 0 {
		c.Cache.MinPositiveTTL = 30 * time.Second
	}
	if c.Cache.MaxPositiveTTL == 0 {
		c.Cache.MaxPositiveTTL = 300 * time.Second
	}
	if c.Cache.NegativeTTL == 0 {
		c.Cache.NegativeTTL = 30 * time.Second
	}
	if c.Cache.StaleIfError == 0 {
		c.Cache.StaleIfError = 10 * time.Minute
	}
	if c.Cache.ResponseBrowserMaxAge == 0 {
		c.Cache.ResponseBrowserMaxAge = 120 * time.Second
	}
	if c.Cache.ResponseSharedMaxAge == 0 {
		c.Cache.ResponseSharedMaxAge = 300 * time.Second
	}
	if c.Cache.ResponseStaleWhileRevalidate == 0 {
		c.Cache.ResponseStaleWhileRevalidate = 30 * time.Second
	}
	if c.Cache.ResponseStaleIfError == 0 {
		c.Cache.ResponseStaleIfError = 10 * time.Minute
	}
	if c.CNLearning.Mode == "" {
		c.CNLearning.Mode = "all_answers_cn"
	}
	if c.CNLearning.TTLFloor == 0 {
		c.CNLearning.TTLFloor = 60 * time.Second
	}
	if c.CNLearning.TTLCap == 0 {
		c.CNLearning.TTLCap = 10 * time.Minute
	}
	if c.Account.BaseURL == "" {
		c.Account.BaseURL = "https://gateway.js.gripe/api/v1/myaccount"
	}
	if c.Storage.DBPath == "" {
		c.Storage.DBPath = "/var/lib/dqueryd/dquery.sqlite3"
	}
	for name, up := range c.Upstreams {
		if up.Method == "" {
			up.Method = "POST"
		}
		if up.Timeout == 0 {
			up.Timeout = 5 * time.Second
		}
		if up.Headers == nil {
			up.Headers = map[string]string{}
		}
		if up.HTTPVersion == "" {
			up.HTTPVersion = "auto"
		}
		if up.HMAC.Enabled && up.HMAC.SecretEnv == "" {
			up.HMAC.SecretEnv = "DQUERY_HMAC_SECRET"
		}
		c.Upstreams[name] = up
	}
}

func (c *Config) Validate() error {
	if c.ChinaRules.CompactJSONPath == "" {
		return fmt.Errorf("china_rules.compact_json_path is required")
	}
	if c.Routing.CN.Upstream == "" {
		return fmt.Errorf("routing.cn.upstream is required")
	}
	if c.Routing.Global.Upstream == "" {
		return fmt.Errorf("routing.global.upstream is required")
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	for _, name := range []string{c.Routing.CN.Upstream, c.Routing.Global.Upstream} {
		if _, ok := c.Upstreams[name]; !ok {
			return fmt.Errorf("referenced upstream %q not found", name)
		}
	}
	for routeName, route := range map[string]RouteConfig{"cn": c.Routing.CN, "global": c.Routing.Global} {
		if route.FallbackUpstream != "" {
			if _, ok := c.Upstreams[route.FallbackUpstream]; !ok {
				return fmt.Errorf("routing.%s.fallback_upstream %q not found", routeName, route.FallbackUpstream)
			}
		}
		switch route.ECSSource {
		case "", "none", "visitor", "client":
		default:
			return fmt.Errorf("routing.%s.ecs_source must be none|visitor|client", routeName)
		}
	}
	if c.CNLearning.Enabled {
		switch c.CNLearning.Mode {
		case "all_answers_cn":
		default:
			return fmt.Errorf("cn_learning.mode must be all_answers_cn")
		}
	}
	for name, up := range c.Upstreams {
		if up.Type == "" {
			up.Type = "doh_wire"
		}
		if up.Type != "doh_wire" {
			return fmt.Errorf("upstreams.%s.type must be doh_wire", name)
		}
		if up.URL == "" {
			return fmt.Errorf("upstreams.%s.url is required", name)
		}
		switch up.Method {
		case "", "GET", "POST":
		default:
			return fmt.Errorf("upstreams.%s.method must be GET|POST", name)
		}
		switch up.HTTPVersion {
		case "", "auto", "h1":
		default:
			return fmt.Errorf("upstreams.%s.http_version must be auto|h1", name)
		}
	}
	return nil
}
