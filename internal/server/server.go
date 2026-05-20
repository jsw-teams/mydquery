package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"

	"gateway-dquery-go/internal/account"
	"gateway-dquery-go/internal/cache"
	"gateway-dquery-go/internal/chinarules"
	"gateway-dquery-go/internal/config"
	"gateway-dquery-go/internal/doh"
	"gateway-dquery-go/internal/ecs"
)

type inflightCall struct {
	done   chan struct{}
	result *doh.Result
	err    error
}

type App struct {
	cfg       *config.Config
	rules     *chinarules.Store
	resolver  *doh.Resolver
	cache     *cache.Cache
	account   *account.Client
	store     *accountStore
	startedAt time.Time

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall
	actionMu   sync.Mutex
	actionLast map[string]time.Time
}

type knownRuleSet struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	SourceURL   string `json:"source_url"`
	Status      string `json:"status"`
	DomainCount int    `json:"domain_count"`
	Enabled     bool   `json:"enabled"`
	LastSyncAt  string `json:"last_sync_at,omitempty"`
	UpdatedAt   string `json:"updated_at"`
	Error       string `json:"error,omitempty"`
}

type domainAction struct {
	ID          string `json:"id"`
	OwnerUserID string `json:"owner_user_id"`
	Domain      string `json:"domain"`
	MatchType   string `json:"match_type"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

var famousRuleSets = []knownRuleSet{
	{ID: "hagezi_multi_normal", Name: "HaGeZi Multi NORMAL", SourceURL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt"},
	{ID: "hagezi_tif", Name: "HaGeZi Threat Intelligence", SourceURL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt"},
	{ID: "adguard_dns_filter", Name: "AdGuard DNS filter", SourceURL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"},
	{ID: "oisd_big", Name: "OISD Big", SourceURL: "https://big.oisd.nl/domainswild2"},
}

func New(cfg *config.Config, rules *chinarules.Store, resolver *doh.Resolver) (*App, error) {
	var c *cache.Cache
	if cfg.Cache.Enabled {
		c = cache.New(cfg.Cache.MaxItems)
	}
	store, err := newAccountStore(cfg.Storage.DBPath)
	if err != nil {
		return nil, err
	}
	return &App{
		cfg:        cfg,
		rules:      rules,
		resolver:   resolver,
		cache:      c,
		account:    account.NewClient(cfg.Account),
		store:      store,
		startedAt:  time.Now().UTC(),
		inflight:   map[string]*inflightCall{},
		actionLast: map[string]time.Time{},
	}, nil
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/account/start", a.handleAuthStart)
	mux.HandleFunc("/auth/account/callback", a.handleAuthCallback)
	mux.HandleFunc("/api/v1/dquery", a.handleDoH)
	mux.HandleFunc("/api/v1/dquery/", a.handleSubpath)
	mux.HandleFunc("/api/v1/dquery/healthz", a.handleHealthz)
	mux.HandleFunc("/api/v1/dquery/readyz", a.handleReadyz)
	mux.HandleFunc("/api/v1/dquery/account/client", a.handleAccountClient)
	mux.HandleFunc("/api/v1/dquery/account/me", a.handleAccountMe)
	return withCommonHeaders(mux)
}

func (a *App) handleSubpath(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/dquery/healthz":
		a.handleHealthz(w, r)
	case "/api/v1/dquery/readyz":
		a.handleReadyz(w, r)
	case "/api/v1/dquery/account/client":
		a.handleAccountClient(w, r)
	case "/api/v1/dquery/account/me":
		a.handleAccountMe(w, r)
	case "/api/v1/dquery/":
		a.handleDoH(w, r)
	default:
		if a.handleAccountAPI(w, r) {
			return
		}
		if a.handlePersonalDoH(w, r) {
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found", "message": "resource not found", "path": r.URL.Path})
	}
}

func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"status":     "healthy",
		"service":    "dqueryd",
		"started_at": a.startedAt.Format(time.RFC3339),
	})
}

func (a *App) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if a.rules == nil || a.resolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "status": "not_ready"})
		return
	}
	payload := map[string]any{
		"ok":         true,
		"status":     "ready",
		"service":    "dqueryd",
		"started_at": a.startedAt.Format(time.RFC3339),
	}
	if a.cache != nil {
		payload["cache"] = a.cache.Stats()
	}
	writeJSON(w, http.StatusOK, payload)
}

func (a *App) handleAccountClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
		return
	}
	if !a.cfg.Account.Enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "account_integration_disabled"})
		return
	}
	clientID := strings.TrimSpace(a.cfg.Account.ClientID)
	loginURL := strings.TrimSpace(a.cfg.Account.LoginURL)
	redirectURI := strings.TrimSpace(a.cfg.Account.RedirectURI)
	if loginURL == "" {
		loginURL = "https://account.js.gripe/login"
	}
	if redirectURI == "" {
		redirectURI = "https://dns.js.gripe/login/"
	}
	scopes := a.cfg.Account.Scopes
	if len(scopes) == 0 {
		scopes = []string{"accounts:read", "identities:resolve"}
	}
	if clientID == "" || strings.EqualFold(clientID, "dquery") || strings.Contains(clientID, "REPLACE") || strings.Contains(clientID, "[") {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "account_client_not_configured"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"client": map[string]any{
			"name":         strings.TrimSpace(a.cfg.Account.ClientName),
			"client_id":    clientID,
			"login_url":    loginURL,
			"redirect_uri": redirectURI,
			"scopes":       scopes,
		},
	})
}

func (a *App) handleAccountMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
		return
	}
	if !a.cfg.Account.Enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "account_integration_disabled"})
		return
	}
	user, err := a.account.Me(r.Context(), account.BearerToken(r))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid_account_session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"user": map[string]any{
			"id":                   user.ID,
			"email":                user.Email,
			"display_name":         user.DisplayName,
			"role":                 user.Role,
			"must_change_password": user.MustChangePassword,
		},
		"resource_owner_id": user.ID,
		"next": map[string]any{
			"profile_table": "user_dns_profiles",
			"purpose":       "use this id to load customized DNS routing, upstreams, and personal rule overlays",
		},
	})
}

func (a *App) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
		return
	}
	if !a.cfg.Account.Enabled {
		http.Redirect(w, r, "/login?error=account_disabled", http.StatusFound)
		return
	}
	clientID := strings.TrimSpace(a.cfg.Account.ClientID)
	if clientID == "" || strings.Contains(clientID, "[") || strings.Contains(clientID, "REPLACE") {
		http.Redirect(w, r, "/login?error=account_client_not_configured", http.StatusFound)
		return
	}
	loginURL := strings.TrimSpace(a.cfg.Account.LoginURL)
	if loginURL == "" {
		loginURL = "https://account.js.gripe/login"
	}
	redirectURI := strings.TrimSpace(a.cfg.Account.RedirectURI)
	if redirectURI == "" {
		redirectURI = requestOrigin(r) + "/auth/account/callback"
	}
	scopes := a.cfg.Account.Scopes
	if len(scopes) == 0 {
		scopes = []string{"accounts:read", "identities:resolve"}
	}
	state := "st_" + randomHex(16)
	http.SetCookie(w, &http.Cookie{
		Name:     "dquery_oauth_state",
		Value:    state,
		Path:     "/auth/account",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	u, err := url.Parse(loginURL)
	if err != nil {
		http.Redirect(w, r, "/login?error=bad_login_url", http.StatusFound)
		return
	}
	q := u.Query()
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("prompt", "consent")
	if r.URL.Query().Get("popup") == "1" {
		q.Set("popup", "1")
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *App) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
		return
	}
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		a.popupHTML(w, false, "/login?error=auth_failed", "账户授权未完成")
		return
	}
	state := r.URL.Query().Get("state")
	c, err := r.Cookie("dquery_oauth_state")
	if err != nil || c.Value == "" || state == "" || c.Value != state {
		a.popupHTML(w, false, "/login?error=state", "登录状态校验失败，请重新打开登录窗口")
		return
	}
	accountSession := r.URL.Query().Get("account_session")
	if accountSession == "" {
		a.popupHTML(w, false, "/login?error=no_session", "账户中心未返回有效登录状态")
		return
	}
	user, err := a.account.Me(r.Context(), accountSession)
	if err != nil {
		a.popupHTML(w, false, "/login?error=account_error", "统一账户校验失败，请稍后重试")
		return
	}
	if user.UserType == "" {
		user.UserType = user.Role
	}
	a.store.ensureDefaultProfile(user)
	if err := a.createSession(w, r, user); err != nil {
		a.popupHTML(w, false, "/login?error=session", "DNS 控制台会话创建失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "dquery_oauth_state",
		Value:    "",
		Path:     "/auth/account",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	a.popupHTML(w, true, "/console/", "登录成功")
}

func (a *App) popupHTML(w http.ResponseWriter, ok bool, redirectTo, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	status := "error"
	if ok {
		status = "ok"
	}
	encMsg, _ := json.Marshal(message)
	encTo, _ := json.Marshal(redirectTo)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>dquery login</title><body>
<script>
const payload={source:"dquery-auth",status:%q,message:%s,redirectTo:%s};
try{ if(window.opener){ window.opener.postMessage(payload, window.location.origin); window.close(); } else { location.href=payload.redirectTo; } }
catch(e){ location.href=payload.redirectTo; }
</script>
<p>%s</p></body>`, status, encMsg, encTo, message)
}

type accountStore struct {
	mu sync.Mutex
	db *sql.DB
}

type accountSession struct {
	ID        string
	User      account.User
	ExpiresAt time.Time
}

type dnsProfile struct {
	ID                    string `json:"id"`
	OwnerUserID           string `json:"owner_user_id"`
	Name                  string `json:"name"`
	Enabled               bool   `json:"enabled"`
	DefaultRoute          string `json:"default_route"`
	DefaultUpstreamPolicy string `json:"default_upstream_policy"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
}

type dnsRule struct {
	ID             string `json:"id"`
	ProfileID      string `json:"profile_id"`
	OwnerUserID    string `json:"owner_user_id"`
	Pattern        string `json:"pattern"`
	MatchType      string `json:"match_type"`
	Route          string `json:"route"`
	UpstreamPolicy string `json:"upstream_policy"`
	Enabled        bool   `json:"enabled"`
	Priority       int    `json:"priority"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type dnsProfileToken struct {
	ID          string `json:"id"`
	OwnerUserID string `json:"owner_user_id"`
	ProfileID   string `json:"profile_id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	TokenPrefix string `json:"token_prefix"`
	TokenHash   string `json:"-"`
	Token       string `json:"token,omitempty"`
	LastUsedAt  string `json:"last_used_at,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type dnsRuleSet struct {
	ID           string `json:"id"`
	ProfileID    string `json:"profile_id"`
	OwnerUserID  string `json:"owner_user_id"`
	Name         string `json:"name"`
	SourceURL    string `json:"source_url"`
	Action       string `json:"action"`
	BlockPageURL string `json:"block_page_url,omitempty"`
	Status       string `json:"status"`
	Enabled      bool   `json:"enabled"`
	LastSyncAt   string `json:"last_sync_at,omitempty"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type queryLog struct {
	ID          string `json:"id"`
	OwnerUserID string `json:"owner_user_id"`
	QName       string `json:"qname"`
	QType       string `json:"qtype"`
	Action      string `json:"action"`
	RuleSetName string `json:"ruleset_name,omitempty"`
	ClientIP    string `json:"client_ip,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type blockSettings struct {
	OwnerUserID  string `json:"owner_user_id"`
	Mode         string `json:"mode"`
	BlockPageURL string `json:"block_page_url"`
	UpdatedAt    string `json:"updated_at"`
}

func newAccountStore(dbPath string) (*accountStore, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	store := &accountStore{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *accountStore) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS dns_profiles (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			default_route TEXT NOT NULL DEFAULT 'auto',
			default_upstream_policy TEXT NOT NULL DEFAULT 'balanced',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_profiles_owner ON dns_profiles(owner_user_id)`,
		`CREATE TABLE IF NOT EXISTS dns_rules (
			id TEXT PRIMARY KEY,
			profile_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			pattern TEXT NOT NULL,
			match_type TEXT NOT NULL DEFAULT 'domain_suffix',
			route TEXT NOT NULL DEFAULT 'auto',
			upstream_policy TEXT NOT NULL DEFAULT 'balanced',
			enabled INTEGER NOT NULL DEFAULT 1,
			priority INTEGER NOT NULL DEFAULT 100,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(profile_id) REFERENCES dns_profiles(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_rules_profile ON dns_rules(profile_id, enabled, priority)`,
		`CREATE TABLE IF NOT EXISTS dns_profile_tokens (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			token_prefix TEXT NOT NULL,
			name TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			last_used_at TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(profile_id) REFERENCES dns_profiles(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_profile_tokens_profile ON dns_profile_tokens(profile_id)`,
		`CREATE TABLE IF NOT EXISTS dns_rule_sets (
			id TEXT PRIMARY KEY,
			profile_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			source_url TEXT NOT NULL,
			action TEXT NOT NULL DEFAULT 'block',
			block_page_url TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			enabled INTEGER NOT NULL DEFAULT 1,
			last_sync_at TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			FOREIGN KEY(profile_id) REFERENCES dns_profiles(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_rule_sets_profile ON dns_rule_sets(profile_id, enabled)`,
		`CREATE TABLE IF NOT EXISTS dns_query_logs (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			qname TEXT NOT NULL,
			qtype TEXT NOT NULL,
			action TEXT NOT NULL,
			ruleset_name TEXT NOT NULL DEFAULT '',
			client_ip TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_query_logs_owner ON dns_query_logs(owner_user_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS dns_block_settings (
			owner_user_id TEXT PRIMARY KEY,
			mode TEXT NOT NULL DEFAULT 'nxdomain',
			block_page_url TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS dquery_known_rule_sets (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			source_url TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			domain_count INTEGER NOT NULL DEFAULT 0,
			last_sync_at TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL,
			error TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS dquery_known_rule_domains (
			ruleset_id TEXT NOT NULL,
			domain TEXT NOT NULL,
			PRIMARY KEY (ruleset_id, domain),
			FOREIGN KEY(ruleset_id) REFERENCES dquery_known_rule_sets(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dquery_known_rule_domains_domain ON dquery_known_rule_domains(domain)`,
		`CREATE TABLE IF NOT EXISTS dns_user_rule_set_preferences (
			owner_user_id TEXT NOT NULL,
			ruleset_id TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (owner_user_id, ruleset_id),
			FOREIGN KEY(ruleset_id) REFERENCES dquery_known_rule_sets(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_user_rule_set_preferences_owner ON dns_user_rule_set_preferences(owner_user_id, enabled)`,
		`CREATE TABLE IF NOT EXISTS dns_domain_actions (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			domain TEXT NOT NULL,
			match_type TEXT NOT NULL DEFAULT 'domain_suffix',
			action TEXT NOT NULL DEFAULT 'allow',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_domain_actions_owner ON dns_domain_actions(owner_user_id, enabled, domain)`,
		`CREATE TABLE IF NOT EXISTS account_sessions (
			id TEXT PRIMARY KEY,
			session_hash TEXT NOT NULL UNIQUE,
			account_user_id TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT '',
			display_name TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT '',
			user_type TEXT NOT NULL DEFAULT '',
			capabilities_json TEXT NOT NULL DEFAULT '{}',
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_account_sessions_hash ON account_sessions(session_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_account_sessions_expires ON account_sessions(expires_at)`,
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return err
		}
	}
	_, _ = s.db.Exec(`ALTER TABLE dns_rule_sets ADD COLUMN block_page_url TEXT NOT NULL DEFAULT ''`)
	if err := s.ensureKnownRuleSets(); err != nil {
		return err
	}
	return nil
}

func (a *App) handleAccountAPI(w http.ResponseWriter, r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/dquery")
	if path == r.URL.Path {
		return false
	}
	writeConsoleCORS(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	if path == "/auth/login" && r.Method == http.MethodPost {
		a.handleAccountLogin(w, r)
		return true
	}
	if path == "/logout" && r.Method == http.MethodPost {
		a.clearSession(w, r)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return true
	}
	if path != "/session" && path != "/settings" && path != "/rulesets" && path != "/domain-rules" && path != "/profiles" && path != "/logs" && !strings.HasPrefix(path, "/rulesets/") && !strings.HasPrefix(path, "/domain-rules/") && !strings.HasPrefix(path, "/profiles/") {
		return false
	}
	user, ok := a.requireAccountUser(w, r)
	if !ok {
		return true
	}
	a.store.ensureDefaultProfile(user)

	switch {
	case path == "/session" && r.Method == http.MethodGet:
		a.handleSession(w, user)
	case path == "/settings" && r.Method == http.MethodGet:
		a.handleSettings(w, user)
	case path == "/settings" && r.Method == http.MethodPatch:
		a.handleUpdateSettings(w, r, user)
	case path == "/rulesets" && r.Method == http.MethodGet:
		a.handleFlatListRuleSets(w, user)
	case strings.HasPrefix(path, "/rulesets/") && r.Method == http.MethodPatch:
		a.handleUpdateKnownRuleSetPreference(w, r, user, strings.TrimPrefix(path, "/rulesets/"))
	case path == "/domain-rules" && r.Method == http.MethodGet:
		a.handleListDomainActions(w, user)
	case path == "/domain-rules" && r.Method == http.MethodPost:
		a.handleCreateDomainAction(w, r, user)
	case strings.HasPrefix(path, "/domain-rules/") && r.Method == http.MethodDelete:
		a.handleDeleteDomainAction(w, r, user, strings.TrimPrefix(path, "/domain-rules/"))
	case path == "/logs" && r.Method == http.MethodGet:
		a.handleQueryLogs(w, r, user)
	case path == "/logs" && r.Method == http.MethodDelete:
		a.handleClearQueryLogs(w, r, user)
	case path == "/profiles" && r.Method == http.MethodGet:
		a.handleListProfiles(w, user)
	case path == "/profiles" && r.Method == http.MethodPost:
		a.handleCreateProfile(w, r, user)
	case strings.HasPrefix(path, "/profiles/"):
		a.handleProfileSubresource(w, r, user, strings.TrimPrefix(path, "/profiles/"))
	default:
		return false
	}
	return true
}

func writeConsoleCORS(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if !isAllowedConsoleOrigin(origin) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", "600")
}

func isAllowedConsoleOrigin(origin string) bool {
	if origin == "https://dns.js.gripe" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" {
		return false
	}
	return u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
}

func (a *App) handleAccountLogin(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.Account.Enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "account_integration_disabled"})
		return
	}
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	result, err := a.account.Login(r.Context(), in.Email, in.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "bad_credentials"})
		return
	}
	if result.User.UserType == "" {
		result.User.UserType = result.User.Role
	}
	a.store.ensureDefaultProfile(result.User)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      result.Token,
		"expires_at": result.ExpiresAt,
		"user": map[string]any{
			"id":           result.User.ID,
			"email":        result.User.Email,
			"display_name": result.User.DisplayName,
			"role":         result.User.Role,
			"user_type":    result.User.UserType,
		},
		"capabilities": dqueryCapabilities(result.User),
	})
}

func (a *App) requireAccountUser(w http.ResponseWriter, r *http.Request) (account.User, bool) {
	var zero account.User
	if !a.cfg.Account.Enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "account_integration_disabled"})
		return zero, false
	}
	if session, err := a.readSession(r); err == nil {
		return session.User, true
	}
	user, err := a.account.Me(r.Context(), account.BearerToken(r))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":        false,
			"error":     "invalid_account_session",
			"login_url": "https://account.js.gripe/login",
		})
		return zero, false
	}
	if user.UserType == "" {
		user.UserType = user.Role
	}
	if strings.EqualFold(user.Status, "disabled") {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "account_disabled", "support_email": "helper@js.gripe"})
		return zero, false
	}
	return user, true
}

func hashSession(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func secureCookie(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func sharedCookieDomain(r *http.Request) string {
	host := r.Host
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	if host == "dns.js.gripe" || host == "gateway.js.gripe" {
		return ".js.gripe"
	}
	return ""
}

func requestOrigin(r *http.Request) string {
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Host
	if host == "" {
		host = "dns.js.gripe"
	}
	return proto + "://" + host
}

func (s *accountStore) ensureDefaultProfile(user account.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM dns_profiles WHERE owner_user_id = ?`, user.ID).Scan(&count); err != nil || count > 0 {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	profile := dnsProfile{
		ID:                    "prof_" + randomHex(8),
		OwnerUserID:           user.ID,
		Name:                  "Default profile",
		Enabled:               true,
		DefaultRoute:          "auto",
		DefaultUpstreamPolicy: "balanced",
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	_, _ = s.db.Exec(`INSERT INTO dns_profiles (id, owner_user_id, name, enabled, default_route, default_upstream_policy, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		profile.ID, profile.OwnerUserID, profile.Name, boolInt(profile.Enabled), profile.DefaultRoute, profile.DefaultUpstreamPolicy, profile.CreatedAt, profile.UpdatedAt)
}

func (a *App) createSession(w http.ResponseWriter, r *http.Request, user account.User) error {
	now := time.Now().UTC()
	raw := "ses_" + randomHex(24)
	ttl := 168 * time.Hour
	expires := now.Add(ttl)
	caps, _ := json.Marshal(user.Capabilities)
	_, err := a.store.db.Exec(`INSERT INTO account_sessions
		(id, session_hash, account_user_id, email, display_name, role, user_type, capabilities_json, expires_at, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"sess_"+randomHex(12), hashSession(raw), user.ID, user.Email, user.DisplayName, user.Role, user.UserType, string(caps),
		expires.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "dquery_session",
		Value:    raw,
		Path:     "/",
		Domain:   sharedCookieDomain(r),
		Expires:  expires,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (a *App) readSession(r *http.Request) (*accountSession, error) {
	c, err := r.Cookie("dquery_session")
	if err != nil || c.Value == "" {
		return nil, sql.ErrNoRows
	}
	var s accountSession
	var capsRaw string
	var expRaw string
	err = a.store.db.QueryRow(`SELECT id, account_user_id, email, display_name, role, user_type, capabilities_json, expires_at
		FROM account_sessions WHERE session_hash = ?`, hashSession(c.Value)).
		Scan(&s.ID, &s.User.ID, &s.User.Email, &s.User.DisplayName, &s.User.Role, &s.User.UserType, &capsRaw, &expRaw)
	if err != nil {
		return nil, err
	}
	exp, err := time.Parse(time.RFC3339, expRaw)
	if err != nil || time.Now().UTC().After(exp) {
		return nil, sql.ErrNoRows
	}
	_ = json.Unmarshal([]byte(capsRaw), &s.User.Capabilities)
	if s.User.Capabilities == nil {
		s.User.Capabilities = map[string]any{}
	}
	s.ExpiresAt = exp
	_, _ = a.store.db.Exec(`UPDATE account_sessions SET last_seen_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), s.ID)
	return &s, nil
}

func (a *App) clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("dquery_session"); err == nil {
		_, _ = a.store.db.Exec(`DELETE FROM account_sessions WHERE session_hash = ?`, hashSession(c.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "dquery_session",
		Value:    "",
		Path:     "/",
		Domain:   sharedCookieDomain(r),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *accountStore) defaultProfileID(ownerID string) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM dns_profiles WHERE owner_user_id = ? ORDER BY created_at LIMIT 1`, ownerID).Scan(&id)
	return id, err
}

func (s *accountStore) getBlockSettings(ownerID string) (blockSettings, error) {
	var settings blockSettings
	err := s.db.QueryRow(`SELECT owner_user_id, mode, block_page_url, updated_at FROM dns_block_settings WHERE owner_user_id = ?`, ownerID).Scan(&settings.OwnerUserID, &settings.Mode, &settings.BlockPageURL, &settings.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return blockSettings{OwnerUserID: ownerID, Mode: "nxdomain", BlockPageURL: "", UpdatedAt: ""}, nil
	}
	return settings, err
}

func (s *accountStore) upsertBlockSettings(settings blockSettings) error {
	_, err := s.db.Exec(`INSERT INTO dns_block_settings (owner_user_id, mode, block_page_url, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(owner_user_id) DO UPDATE SET mode = excluded.mode, block_page_url = excluded.block_page_url, updated_at = excluded.updated_at`,
		settings.OwnerUserID, settings.Mode, settings.BlockPageURL, settings.UpdatedAt)
	return err
}

func (a *App) handleSession(w http.ResponseWriter, user account.User) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"user": map[string]any{
			"id":           user.ID,
			"email":        user.Email,
			"display_name": user.DisplayName,
			"role":         user.Role,
			"user_type":    user.UserType,
		},
		"capabilities": dqueryCapabilities(user),
		"initialized":  true,
	})
}

func (a *App) handleSettings(w http.ResponseWriter, user account.User) {
	settings, err := a.store.getBlockSettings(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": settings})
}

func (a *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request, user account.User) {
	var in struct {
		Mode         string `json:"mode"`
		BlockPageURL string `json:"block_page_url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	settings := blockSettings{
		OwnerUserID:  user.ID,
		Mode:         normalizeChoice(in.Mode, "nxdomain", "nxdomain", "block_page"),
		BlockPageURL: strings.TrimSpace(in.BlockPageURL),
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if settings.Mode == "block_page" {
		if _, ok := blockPageDNSTarget(settings.BlockPageURL); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_block_page_target"})
			return
		}
	}
	if err := a.store.upsertBlockSettings(settings); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": settings})
}

func (a *App) handleFlatListRuleSets(w http.ResponseWriter, user account.User) {
	ruleSets, err := a.store.listKnownRuleSetsForOwner(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rulesets": ruleSets})
}

func (a *App) handleUpdateKnownRuleSetPreference(w http.ResponseWriter, r *http.Request, user account.User, ruleSetID string) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	if in.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "enabled_required"})
		return
	}
	ruleSet, err := a.store.setKnownRuleSetPreference(user.ID, strings.Trim(ruleSetID, "/"), *in.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "ruleset_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ruleset": ruleSet})
}

func (a *App) handleQueryLogs(w http.ResponseWriter, r *http.Request, user account.User) {
	logs, err := a.store.listQueryLogs(user.ID, r.URL.Query().Get("q"), r.URL.Query().Get("limit"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "logs": logs})
}

func (a *App) handleClearQueryLogs(w http.ResponseWriter, r *http.Request, user account.User) {
	if !a.allowUserAction(user.ID, "clear_logs", 30*time.Second) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "rate_limited", "retry_after_seconds": 30})
		return
	}
	if err := a.store.clearQueryLogs(user.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleListDomainActions(w http.ResponseWriter, user account.User) {
	rules, err := a.store.listDomainActions(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": rules})
}

func (a *App) handleCreateDomainAction(w http.ResponseWriter, r *http.Request, user account.User) {
	var in struct {
		Domain    string `json:"domain"`
		MatchType string `json:"match_type"`
		Action    string `json:"action"`
		Enabled   *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	domain := normalizeDomain(in.Domain)
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "domain_required"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rule := domainAction{
		ID:          "act_" + randomHex(8),
		OwnerUserID: user.ID,
		Domain:      domain,
		MatchType:   normalizeChoice(in.MatchType, "domain_suffix", "domain_suffix", "exact"),
		Action:      normalizeChoice(in.Action, "allow", "allow", "block"),
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if in.Enabled != nil {
		rule.Enabled = *in.Enabled
	}
	if err := a.store.insertDomainAction(rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "rule": rule})
}

func (a *App) handleDeleteDomainAction(w http.ResponseWriter, r *http.Request, user account.User, id string) {
	if err := a.store.deleteDomainAction(user.ID, strings.Trim(id, "/")); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) allowUserAction(userID, action string, interval time.Duration) bool {
	key := userID + ":" + action
	now := time.Now()
	a.actionMu.Lock()
	defer a.actionMu.Unlock()
	if last, ok := a.actionLast[key]; ok && now.Sub(last) < interval {
		return false
	}
	a.actionLast[key] = now
	return true
}

func (a *App) handleListUpstreams(w http.ResponseWriter) {
	upstreams := make([]map[string]any, 0, len(a.cfg.Upstreams))
	for name, spec := range a.cfg.Upstreams {
		upstreams = append(upstreams, map[string]any{
			"name":         name,
			"type":         spec.Type,
			"method":       spec.Method,
			"http_version": spec.HTTPVersion,
			"timeout":      spec.Timeout.String(),
			"tested":       true,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"upstreams": upstreams,
		"policies":  []string{"balanced", "privacy", "low_latency"},
	})
}

func (a *App) handleListProfiles(w http.ResponseWriter, user account.User) {
	profiles, err := a.store.listProfiles(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "profiles": profiles})
}

func (a *App) handleCreateProfile(w http.ResponseWriter, r *http.Request, user account.User) {
	var in struct {
		Name                  string `json:"name"`
		Enabled               *bool  `json:"enabled"`
		DefaultRoute          string `json:"default_route"`
		DefaultUpstreamPolicy string `json:"default_upstream_policy"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = "Personal profile"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	profile := dnsProfile{
		ID: "prof_" + randomHex(8), OwnerUserID: user.ID, Name: in.Name, Enabled: true,
		DefaultRoute:          normalizeChoice(in.DefaultRoute, "auto", "auto", "cn", "global"),
		DefaultUpstreamPolicy: normalizeChoice(in.DefaultUpstreamPolicy, "balanced", "balanced", "privacy", "low_latency"),
		CreatedAt:             now, UpdatedAt: now,
	}
	if in.Enabled != nil {
		profile.Enabled = *in.Enabled
	}
	if err := a.store.insertProfile(profile); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "profile": profile})
}

func (a *App) handleProfileSubresource(w http.ResponseWriter, r *http.Request, user account.User, tail string) {
	parts := strings.Split(strings.Trim(tail, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found"})
		return
	}
	profileID := parts[0]
	if !a.store.userOwnsProfile(user.ID, profileID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "profile_not_found"})
		return
	}
	if len(parts) == 2 && parts[1] == "rules" {
		if r.Method == http.MethodGet {
			rules, err := a.store.listRules(profileID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": rules})
			return
		}
		if r.Method == http.MethodPost {
			a.handleCreateRule(w, r, user, profileID)
			return
		}
	}
	if len(parts) == 2 && parts[1] == "tokens" {
		if r.Method == http.MethodGet {
			tokens, err := a.store.listTokens(profileID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tokens": tokens})
			return
		}
		if r.Method == http.MethodPost {
			a.handleCreateToken(w, r, user, profileID)
			return
		}
	}
	if len(parts) == 2 && parts[1] == "rulesets" {
		if r.Method == http.MethodGet {
			ruleSets, err := a.store.listRuleSets(profileID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rulesets": ruleSets})
			return
		}
		if r.Method == http.MethodPost {
			a.handleCreateRuleSet(w, r, user, profileID)
			return
		}
	}
	if len(parts) == 3 && parts[1] == "rulesets" && r.Method == http.MethodDelete {
		if err := a.store.deleteRuleSet(user.ID, profileID, parts[2]); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found"})
}

func (a *App) handleCreateRule(w http.ResponseWriter, r *http.Request, user account.User, profileID string) {
	var in struct {
		Pattern        string `json:"pattern"`
		MatchType      string `json:"match_type"`
		Route          string `json:"route"`
		UpstreamPolicy string `json:"upstream_policy"`
		Enabled        *bool  `json:"enabled"`
		Priority       int    `json:"priority"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	pattern := strings.Trim(strings.ToLower(in.Pattern), ". ")
	if pattern == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "pattern_required"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rule := dnsRule{
		ID: "rule_" + randomHex(8), ProfileID: profileID, OwnerUserID: user.ID, Pattern: pattern,
		MatchType:      normalizeChoice(in.MatchType, "domain_suffix", "domain_suffix", "exact"),
		Route:          normalizeChoice(in.Route, "auto", "auto", "cn", "global"),
		UpstreamPolicy: normalizeChoice(in.UpstreamPolicy, "balanced", "balanced", "privacy", "low_latency"),
		Enabled:        true, Priority: in.Priority, CreatedAt: now, UpdatedAt: now,
	}
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	if in.Enabled != nil {
		rule.Enabled = *in.Enabled
	}
	if err := a.store.insertRule(rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "rule": rule})
}

func (a *App) handleCreateToken(w http.ResponseWriter, r *http.Request, user account.User, profileID string) {
	var in struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in)
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "DoH client"
	}
	raw := "dq_" + randomHex(18)
	sum := sha256.Sum256([]byte(raw))
	now := time.Now().UTC().Format(time.RFC3339)
	token := dnsProfileToken{
		ID: "tok_" + randomHex(8), OwnerUserID: user.ID, ProfileID: profileID, Name: name, Status: "active",
		TokenPrefix: raw[:10], TokenHash: hex.EncodeToString(sum[:]), Token: raw, CreatedAt: now, UpdatedAt: now,
	}
	if err := a.store.insertToken(token); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "token": token})
}

func (a *App) handleCreateRuleSet(w http.ResponseWriter, r *http.Request, user account.User, profileID string) {
	var in struct {
		Name      string `json:"name"`
		SourceURL string `json:"source_url"`
		Action    string `json:"action"`
		Enabled   *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_json"})
		return
	}
	name := strings.TrimSpace(in.Name)
	sourceURL := strings.TrimSpace(in.SourceURL)
	if name == "" || sourceURL == "" || !(strings.HasPrefix(sourceURL, "https://") || strings.HasPrefix(sourceURL, "http://")) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_ruleset"})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	ruleSet := dnsRuleSet{
		ID: "set_" + randomHex(8), ProfileID: profileID, OwnerUserID: user.ID, Name: name, SourceURL: sourceURL,
		Action: normalizeChoice(in.Action, "nxdomain", "nxdomain", "block_page", "allow"), Status: "pending", Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if in.Enabled != nil {
		ruleSet.Enabled = *in.Enabled
	}
	if err := a.store.insertRuleSet(ruleSet); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "storage_error"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "ruleset": ruleSet})
}

func (s *accountStore) userOwnsProfile(ownerID, profileID string) bool {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM dns_profiles WHERE owner_user_id = ? AND id = ?`, ownerID, profileID).Scan(&count)
	return err == nil && count > 0
}

func (s *accountStore) listProfiles(ownerID string) ([]dnsProfile, error) {
	rows, err := s.db.Query(`SELECT id, owner_user_id, name, enabled, default_route, default_upstream_policy, created_at, updated_at FROM dns_profiles WHERE owner_user_id = ? ORDER BY created_at`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var profiles []dnsProfile
	for rows.Next() {
		var profile dnsProfile
		var enabled int
		if err := rows.Scan(&profile.ID, &profile.OwnerUserID, &profile.Name, &enabled, &profile.DefaultRoute, &profile.DefaultUpstreamPolicy, &profile.CreatedAt, &profile.UpdatedAt); err != nil {
			return nil, err
		}
		profile.Enabled = enabled != 0
		profiles = append(profiles, profile)
	}
	return profiles, rows.Err()
}

func (s *accountStore) insertProfile(profile dnsProfile) error {
	_, err := s.db.Exec(`INSERT INTO dns_profiles (id, owner_user_id, name, enabled, default_route, default_upstream_policy, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		profile.ID, profile.OwnerUserID, profile.Name, boolInt(profile.Enabled), profile.DefaultRoute, profile.DefaultUpstreamPolicy, profile.CreatedAt, profile.UpdatedAt)
	return err
}

func (s *accountStore) listRules(profileID string) ([]dnsRule, error) {
	rows, err := s.db.Query(`SELECT id, profile_id, owner_user_id, pattern, match_type, route, upstream_policy, enabled, priority, created_at, updated_at FROM dns_rules WHERE profile_id = ? ORDER BY enabled DESC, priority ASC, created_at ASC`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []dnsRule
	for rows.Next() {
		var rule dnsRule
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.ProfileID, &rule.OwnerUserID, &rule.Pattern, &rule.MatchType, &rule.Route, &rule.UpstreamPolicy, &enabled, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, err
		}
		rule.Enabled = enabled != 0
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *accountStore) insertRule(rule dnsRule) error {
	_, err := s.db.Exec(`INSERT INTO dns_rules (id, profile_id, owner_user_id, pattern, match_type, route, upstream_policy, enabled, priority, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.ProfileID, rule.OwnerUserID, rule.Pattern, rule.MatchType, rule.Route, rule.UpstreamPolicy, boolInt(rule.Enabled), rule.Priority, rule.CreatedAt, rule.UpdatedAt)
	return err
}

func (s *accountStore) listTokens(profileID string) ([]dnsProfileToken, error) {
	rows, err := s.db.Query(`SELECT id, owner_user_id, profile_id, token_hash, token_prefix, name, status, COALESCE(last_used_at, ''), created_at, updated_at FROM dns_profile_tokens WHERE profile_id = ? ORDER BY created_at DESC`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []dnsProfileToken
	for rows.Next() {
		var token dnsProfileToken
		if err := rows.Scan(&token.ID, &token.OwnerUserID, &token.ProfileID, &token.TokenHash, &token.TokenPrefix, &token.Name, &token.Status, &token.LastUsedAt, &token.CreatedAt, &token.UpdatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *accountStore) insertToken(token dnsProfileToken) error {
	_, err := s.db.Exec(`INSERT INTO dns_profile_tokens (id, owner_user_id, profile_id, token_hash, token_prefix, name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token.ID, token.OwnerUserID, token.ProfileID, token.TokenHash, token.TokenPrefix, token.Name, token.Status, token.CreatedAt, token.UpdatedAt)
	return err
}

func (s *accountStore) listRuleSets(profileID string) ([]dnsRuleSet, error) {
	rows, err := s.db.Query(`SELECT id, profile_id, owner_user_id, name, source_url, action, status, enabled, COALESCE(last_sync_at, ''), created_at, updated_at FROM dns_rule_sets WHERE profile_id = ? ORDER BY enabled DESC, created_at DESC`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ruleSets []dnsRuleSet
	for rows.Next() {
		var ruleSet dnsRuleSet
		var enabled int
		if err := rows.Scan(&ruleSet.ID, &ruleSet.ProfileID, &ruleSet.OwnerUserID, &ruleSet.Name, &ruleSet.SourceURL, &ruleSet.Action, &ruleSet.Status, &enabled, &ruleSet.LastSyncAt, &ruleSet.CreatedAt, &ruleSet.UpdatedAt); err != nil {
			return nil, err
		}
		ruleSet.Enabled = enabled != 0
		ruleSets = append(ruleSets, ruleSet)
	}
	return ruleSets, rows.Err()
}

func (s *accountStore) insertRuleSet(ruleSet dnsRuleSet) error {
	_, err := s.db.Exec(`INSERT INTO dns_rule_sets (id, profile_id, owner_user_id, name, source_url, action, status, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ruleSet.ID, ruleSet.ProfileID, ruleSet.OwnerUserID, ruleSet.Name, ruleSet.SourceURL, ruleSet.Action, ruleSet.Status, boolInt(ruleSet.Enabled), ruleSet.CreatedAt, ruleSet.UpdatedAt)
	return err
}

func (s *accountStore) deleteRuleSet(ownerID, profileID, ruleSetID string) error {
	_, err := s.db.Exec(`DELETE FROM dns_rule_sets WHERE owner_user_id = ? AND profile_id = ? AND id = ?`, ownerID, profileID, ruleSetID)
	return err
}

func (s *accountStore) ensureKnownRuleSets() error {
	now := time.Now().UTC().Format(time.RFC3339)
	for _, set := range famousRuleSets {
		if _, err := s.db.Exec(`INSERT INTO dquery_known_rule_sets (id, name, source_url, status, updated_at) VALUES (?, ?, ?, 'pending', ?)
			ON CONFLICT(id) DO UPDATE SET name = excluded.name, source_url = excluded.source_url, updated_at = CASE WHEN dquery_known_rule_sets.updated_at = '' THEN excluded.updated_at ELSE dquery_known_rule_sets.updated_at END`,
			set.ID, set.Name, set.SourceURL, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *accountStore) listKnownRuleSets() ([]knownRuleSet, error) {
	rows, err := s.db.Query(`SELECT id, name, source_url, status, domain_count, COALESCE(last_sync_at, ''), updated_at, COALESCE(error, '') FROM dquery_known_rule_sets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sets []knownRuleSet
	for rows.Next() {
		var set knownRuleSet
		if err := rows.Scan(&set.ID, &set.Name, &set.SourceURL, &set.Status, &set.DomainCount, &set.LastSyncAt, &set.UpdatedAt, &set.Error); err != nil {
			return nil, err
		}
		sets = append(sets, set)
	}
	return sets, rows.Err()
}

func (s *accountStore) listKnownRuleSetsForOwner(ownerID string) ([]knownRuleSet, error) {
	rows, err := s.db.Query(`SELECT s.id, s.name, s.source_url, s.status, s.domain_count, COALESCE(p.enabled, 0), COALESCE(s.last_sync_at, ''), s.updated_at, COALESCE(s.error, '')
		FROM dquery_known_rule_sets s
		LEFT JOIN dns_user_rule_set_preferences p ON p.ruleset_id = s.id AND p.owner_user_id = ?
		ORDER BY s.name`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sets := []knownRuleSet{}
	for rows.Next() {
		var set knownRuleSet
		var enabled int
		if err := rows.Scan(&set.ID, &set.Name, &set.SourceURL, &set.Status, &set.DomainCount, &enabled, &set.LastSyncAt, &set.UpdatedAt, &set.Error); err != nil {
			return nil, err
		}
		set.Enabled = enabled != 0
		sets = append(sets, set)
	}
	return sets, rows.Err()
}

func (s *accountStore) setKnownRuleSetPreference(ownerID, ruleSetID string, enabled bool) (knownRuleSet, error) {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM dquery_known_rule_sets WHERE id = ?`, ruleSetID).Scan(&exists); err != nil {
		return knownRuleSet{}, err
	}
	if exists == 0 {
		return knownRuleSet{}, sql.ErrNoRows
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO dns_user_rule_set_preferences (owner_user_id, ruleset_id, enabled, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(owner_user_id, ruleset_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at`,
		ownerID, ruleSetID, boolInt(enabled), now); err != nil {
		return knownRuleSet{}, err
	}
	sets, err := s.listKnownRuleSetsForOwner(ownerID)
	if err != nil {
		return knownRuleSet{}, err
	}
	for _, set := range sets {
		if set.ID == ruleSetID {
			return set, nil
		}
	}
	return knownRuleSet{}, sql.ErrNoRows
}

func (s *accountStore) staleKnownRuleSets(maxAge time.Duration) ([]knownRuleSet, error) {
	sets, err := s.listKnownRuleSets()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var stale []knownRuleSet
	for _, set := range sets {
		if set.LastSyncAt == "" || set.DomainCount == 0 {
			stale = append(stale, set)
			continue
		}
		last, err := time.Parse(time.RFC3339, set.LastSyncAt)
		if err != nil || now.Sub(last) >= maxAge {
			stale = append(stale, set)
		}
	}
	return stale, nil
}

func (s *accountStore) replaceKnownRuleDomains(set knownRuleSet, domains []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`DELETE FROM dquery_known_rule_domains WHERE ruleset_id = ?`, set.ID); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO dquery_known_rule_domains (ruleset_id, domain) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	count := 0
	for _, domain := range domains {
		if _, err := stmt.Exec(set.ID, domain); err != nil {
			_ = stmt.Close()
			return err
		}
		count++
	}
	_ = stmt.Close()
	if _, err := tx.Exec(`UPDATE dquery_known_rule_sets SET status = 'synced', domain_count = ?, last_sync_at = ?, updated_at = ?, error = '' WHERE id = ?`, count, now, now, set.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *accountStore) markKnownRuleSetError(setID string, errText string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if len(errText) > 240 {
		errText = errText[:240]
	}
	_, _ = s.db.Exec(`UPDATE dquery_known_rule_sets SET status = CASE WHEN domain_count > 0 THEN status ELSE 'error' END, updated_at = ?, error = ? WHERE id = ?`, now, errText, setID)
}

func (s *accountStore) knownRuleSetMatch(ownerID, domain string) (string, bool) {
	domain = normalizeDomain(domain)
	for candidate := domain; candidate != ""; candidate = parentDomain(candidate) {
		var name string
		err := s.db.QueryRow(`SELECT s.name
			FROM dquery_known_rule_domains d
			JOIN dquery_known_rule_sets s ON s.id = d.ruleset_id
			JOIN dns_user_rule_set_preferences p ON p.ruleset_id = s.id AND p.owner_user_id = ? AND p.enabled = 1
			WHERE d.domain = ? AND s.status = 'synced'
			LIMIT 1`, ownerID, candidate).Scan(&name)
		if err == nil {
			return name, true
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", false
		}
	}
	return "", false
}

func (s *accountStore) listDomainActions(ownerID string) ([]domainAction, error) {
	rows, err := s.db.Query(`SELECT id, owner_user_id, domain, match_type, action, enabled, created_at, updated_at FROM dns_domain_actions WHERE owner_user_id = ? ORDER BY enabled DESC, updated_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []domainAction{}
	for rows.Next() {
		var rule domainAction
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.OwnerUserID, &rule.Domain, &rule.MatchType, &rule.Action, &enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, err
		}
		rule.Enabled = enabled != 0
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *accountStore) insertDomainAction(rule domainAction) error {
	_, err := s.db.Exec(`INSERT INTO dns_domain_actions (id, owner_user_id, domain, match_type, action, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.OwnerUserID, rule.Domain, rule.MatchType, rule.Action, boolInt(rule.Enabled), rule.CreatedAt, rule.UpdatedAt)
	return err
}

func (s *accountStore) deleteDomainAction(ownerID, ruleID string) error {
	_, err := s.db.Exec(`DELETE FROM dns_domain_actions WHERE owner_user_id = ? AND id = ?`, ownerID, ruleID)
	return err
}

func (s *accountStore) domainActionFor(ownerID, qname string) (domainAction, bool) {
	rows, err := s.db.Query(`SELECT id, owner_user_id, domain, match_type, action, enabled, created_at, updated_at FROM dns_domain_actions WHERE owner_user_id = ? AND enabled = 1 ORDER BY updated_at DESC`, ownerID)
	if err != nil {
		return domainAction{}, false
	}
	defer rows.Close()
	qname = normalizeDomain(qname)
	for rows.Next() {
		var rule domainAction
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.OwnerUserID, &rule.Domain, &rule.MatchType, &rule.Action, &enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return domainAction{}, false
		}
		rule.Enabled = enabled != 0
		if domainActionMatches(rule, qname) {
			return rule, true
		}
	}
	return domainAction{}, false
}

func (s *accountStore) insertQueryLog(logEntry queryLog) {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	_, _ = s.db.Exec(`DELETE FROM dns_query_logs WHERE created_at < ?`, cutoff)
	_, _ = s.db.Exec(`INSERT INTO dns_query_logs (id, owner_user_id, qname, qtype, action, ruleset_name, client_ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		logEntry.ID, logEntry.OwnerUserID, logEntry.QName, logEntry.QType, logEntry.Action, logEntry.RuleSetName, logEntry.ClientIP, logEntry.CreatedAt)
}

func (s *accountStore) listQueryLogs(ownerID, q, limitValue string) ([]queryLog, error) {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	_, _ = s.db.Exec(`DELETE FROM dns_query_logs WHERE created_at < ?`, cutoff)
	limit := 50
	if parsed, err := strconv.Atoi(strings.TrimSpace(limitValue)); err == nil && parsed > 0 && parsed <= 200 {
		limit = parsed
	}
	q = strings.TrimSpace(strings.ToLower(q))
	var rows *sql.Rows
	var err error
	if q == "" {
		rows, err = s.db.Query(`SELECT id, owner_user_id, qname, qtype, action, ruleset_name, client_ip, created_at FROM dns_query_logs WHERE owner_user_id = ? ORDER BY created_at DESC LIMIT ?`, ownerID, limit)
	} else {
		rows, err = s.db.Query(`SELECT id, owner_user_id, qname, qtype, action, ruleset_name, client_ip, created_at FROM dns_query_logs WHERE owner_user_id = ? AND qname LIKE ? ORDER BY created_at DESC LIMIT ?`, ownerID, "%"+q+"%", limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []queryLog
	for rows.Next() {
		var entry queryLog
		if err := rows.Scan(&entry.ID, &entry.OwnerUserID, &entry.QName, &entry.QType, &entry.Action, &entry.RuleSetName, &entry.ClientIP, &entry.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, entry)
	}
	return logs, rows.Err()
}

func (s *accountStore) clearQueryLogs(ownerID string) error {
	_, err := s.db.Exec(`DELETE FROM dns_query_logs WHERE owner_user_id = ?`, ownerID)
	return err
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func normalizeDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.Trim(value, ". ")
	if strings.ContainsAny(value, "/:@") {
		return ""
	}
	return value
}

func parentDomain(domain string) string {
	if i := strings.IndexByte(domain, '.'); i >= 0 && i+1 < len(domain) {
		return domain[i+1:]
	}
	return ""
}

func domainActionMatches(rule domainAction, qname string) bool {
	domain := normalizeDomain(rule.Domain)
	if domain == "" || qname == "" {
		return false
	}
	if rule.MatchType == "exact" {
		return qname == domain
	}
	return qname == domain || strings.HasSuffix(qname, "."+domain)
}

func (s *accountStore) ownerExists(ownerID string) bool {
	var exists int
	err := s.db.QueryRow(`SELECT 1
		FROM dns_profiles
		WHERE owner_user_id = ?
		UNION
		SELECT 1
		FROM dns_block_settings
		WHERE owner_user_id = ?
		UNION
		SELECT 1
		FROM dns_domain_actions
		WHERE owner_user_id = ?
		LIMIT 1`, ownerID, ownerID, ownerID).Scan(&exists)
	return err == nil && exists == 1
}

func parseRuleSetDomains(body io.Reader) []string {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	seen := map[string]struct{}{}
	var domains []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		if i := strings.IndexAny(line, "#!"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) > 1 && (net.ParseIP(fields[0]) != nil || fields[0] == "0.0.0.0" || fields[0] == "::") {
			line = fields[1]
		} else if len(fields) > 0 {
			line = fields[0]
		}
		line = strings.TrimPrefix(line, "||")
		line = strings.TrimPrefix(line, "|")
		line = strings.TrimSuffix(line, "^")
		line = strings.TrimSuffix(line, "$important")
		domain := normalizeDomain(line)
		if domain == "" || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
		if len(domains) >= 500000 {
			break
		}
	}
	return domains
}

func (a *App) RefreshKnownRuleSets(ctx context.Context) error {
	sets, err := a.store.staleKnownRuleSets(7 * 24 * time.Hour)
	if err != nil || len(sets) == 0 {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for _, set := range sets {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, set.SourceURL, nil)
		if err != nil {
			a.store.markKnownRuleSetError(set.ID, err.Error())
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			a.store.markKnownRuleSetError(set.ID, err.Error())
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			a.store.markKnownRuleSetError(set.ID, fmt.Sprintf("http_%d", resp.StatusCode))
			continue
		}
		domains := parseRuleSetDomains(io.LimitReader(resp.Body, 32<<20))
		_ = resp.Body.Close()
		if len(domains) == 0 {
			a.store.markKnownRuleSetError(set.ID, "empty_ruleset")
			continue
		}
		if err := a.store.replaceKnownRuleDomains(set, domains); err != nil {
			a.store.markKnownRuleSetError(set.ID, err.Error())
			continue
		}
		log.Printf("level=info ruleset=%s domains=%d synced=true", set.ID, len(domains))
	}
	return nil
}

func (a *App) StartKnownRuleSetRefresher(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				if err := a.RefreshKnownRuleSets(refreshCtx); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("level=warn refresh_known_rulesets err=%v", err)
				}
				cancel()
			}
		}
	}()
}

func dqueryCapabilities(user account.User) map[string]bool {
	role := user.UserType
	if role == "" {
		role = user.Role
	}
	return map[string]bool{
		"profiles": true,
		"rules":    true,
		"tokens":   true,
		"queries":  true,
		"operate":  role == "system_admin" || role == "operator",
		"audit":    role == "system_admin" || role == "auditor",
		"admin":    role == "system_admin",
	}
}

func normalizeChoice(value, fallback string, allowed ...string) string {
	value = strings.TrimSpace(value)
	for _, item := range allowed {
		if value == item {
			return value
		}
	}
	return fallback
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (a *App) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/dquery" && r.URL.Path != "/api/v1/dquery/" && !isPersonalDoHPath(r.URL.Path) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found", "message": "resource not found", "path": r.URL.Path})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method_not_allowed"})
		return
	}
	if err := validateRequest(r); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_request", "message": err.Error()})
		return
	}

	queryBytes, err := a.readQueryBytes(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad_query", "message": err.Error()})
		return
	}

	var query dns.Msg
	if err := query.Unpack(queryBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_dns_message", "message": err.Error()})
		return
	}
	if len(query.Question) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "missing_question"})
		return
	}

	question := query.Question[0]
	qname := strings.TrimSuffix(strings.ToLower(question.Name), ".")
	qtype := dns.TypeToString[question.Qtype]
	if qtype == "" {
		qtype = fmt.Sprintf("TYPE%d", question.Qtype)
	}
	personalOwnerID := personalUserIDFromPath(r.URL.Path)
	if personalOwnerID != "" {
		if !a.store.ownerExists(personalOwnerID) {
			response := nxdomainResponse(&query)
			a.writeDNSResponse(w, r, http.StatusOK, response, 60, debugHeaders{QName: qname, QType: qtype, CacheStatus: "BYPASS"})
			return
		}
		if action, ok := a.store.domainActionFor(personalOwnerID, qname); ok {
			if action.Action == "block" {
				response := nxdomainResponse(&query)
				if blockResponse, ok := a.blockPageResponse(r.Context(), personalOwnerID, &query); ok {
					response = blockResponse
				}
				a.logPersonalQuery(personalOwnerID, qname, qtype, "block_domain_rule", "", a.extractClientIP(r))
				a.writeDNSResponse(w, r, http.StatusOK, response, 60, debugHeaders{QName: qname, QType: qtype, CacheStatus: "BYPASS"})
				return
			}
		} else if setName, ok := a.store.knownRuleSetMatch(personalOwnerID, qname); ok {
			response := nxdomainResponse(&query)
			if blockResponse, ok := a.blockPageResponse(r.Context(), personalOwnerID, &query); ok {
				response = blockResponse
			}
			a.logPersonalQuery(personalOwnerID, qname, qtype, "block_ruleset", setName, a.extractClientIP(r))
			a.writeDNSResponse(w, r, http.StatusOK, response, 60, debugHeaders{QName: qname, QType: qtype, CacheStatus: "BYPASS"})
			return
		}
	}

	visitorIP := a.extractClientIP(r)
	visitorECS, visitorPresent := ecs.VisitorFromIP(visitorIP, a.cfg.ECS.VisitorV4Mask, a.cfg.ECS.VisitorV6Mask)
	if !visitorPresent {
		visitorECS = ""
	}
	clientECS, _ := a.extractClientECS(r, &query)
	routeName, routeCfg := a.pickRouteForVisitor(qname, visitorIP, r.Header.Get("CF-IPCountry"), time.Now())
	selectedECS, selectedSource := ecs.Select(routeCfg.ECSSource, ecs.Candidates{Visitor: visitorECS, Client: clientECS})
	if routeName == "global" && selectedECS == "" && visitorECS != "" && !isMainlandChinaRequest(visitorIP, r.Header.Get("CF-IPCountry")) {
		selectedECS, selectedSource = visitorECS, "visitor"
	}

	cacheKey := ""
	if a.cache != nil {
		cacheKey = cache.Key(routeName, routeCfg.Upstream, selectedECS, string(queryBytes))
		if cached, ok := a.cache.GetFresh(cacheKey, time.Now()); ok {
			ttl := responseTTL(cached, a.cfg.Cache.DefaultPositiveTTL, a.cfg.Cache.NegativeTTL, a.cfg.Cache.MinPositiveTTL, a.cfg.Cache.MaxPositiveTTL)
			a.logPersonalQuery(personalOwnerID, qname, qtype, "resolve_cache", "", visitorIP)
			a.writeDNSResponse(w, r, http.StatusOK, cached, effectiveResponseCacheTTL(ttl, a.cfg.Cache), debugHeaders{
				Route: routeName, Upstream: routeCfg.Upstream, SelectedECS: selectedECS, ECSSource: selectedSource,
				QName: qname, QType: qtype, CacheStatus: "HIT",
			})
			return
		}
	}

	result, upstreamName, err := a.resolveWithInflight(r.Context(), cacheKey, routeName, routeCfg, &query, queryBytes, selectedECS)
	if err != nil {
		if a.cache != nil && cacheKey != "" {
			if stale, ok := a.cache.GetStale(cacheKey, time.Now()); ok {
				ttl := responseTTL(stale, a.cfg.Cache.DefaultPositiveTTL, a.cfg.Cache.NegativeTTL, a.cfg.Cache.MinPositiveTTL, a.cfg.Cache.MaxPositiveTTL)
				a.writeDNSResponse(w, r, http.StatusOK, stale, effectiveResponseCacheTTL(ttl, a.cfg.Cache), debugHeaders{
					Route: routeName, Upstream: upstreamName, SelectedECS: selectedECS, ECSSource: selectedSource,
					QName: qname, QType: qtype, CacheStatus: "STALE",
				})
				return
			}
		}
		log.Printf("level=error route=%s qname=%s qtype=%s upstream=%s err=%v", routeName, qname, qtype, upstreamName, err)
		a.logPersonalQuery(personalOwnerID, qname, qtype, "error", "", visitorIP)
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "upstream_failure"})
		return
	}

	ttl := responseTTL(result.ResponseBytes, a.cfg.Cache.DefaultPositiveTTL, a.cfg.Cache.NegativeTTL, a.cfg.Cache.MinPositiveTTL, a.cfg.Cache.MaxPositiveTTL)
	if routeName == "global" && a.cfg.CNLearning.Enabled && a.cfg.CNLearning.Mode == "all_answers_cn" && a.rules.ShouldLearnAllAnswersCN(result.ResponseBytes) {
		learnTTL := ttl
		if learnTTL < a.cfg.CNLearning.TTLFloor {
			learnTTL = a.cfg.CNLearning.TTLFloor
		}
		if a.cfg.CNLearning.TTLCap > 0 && learnTTL > a.cfg.CNLearning.TTLCap {
			learnTTL = a.cfg.CNLearning.TTLCap
		}
		a.rules.LearnCNDomain(qname, learnTTL, time.Now())
	}
	if a.cache != nil && cacheKey != "" {
		a.cache.Set(cacheKey, result.ResponseBytes, ttl, a.cfg.Cache.StaleIfError, time.Now())
	}
	log.Printf("level=info route=%s qname=%s qtype=%s upstream=%s ecs_source=%s", routeName, qname, qtype, upstreamName, selectedSource)
	a.logPersonalQuery(personalOwnerID, qname, qtype, "resolve", "", visitorIP)
	a.writeDNSResponse(w, r, http.StatusOK, result.ResponseBytes, effectiveResponseCacheTTL(ttl, a.cfg.Cache), debugHeaders{
		Route: routeName, Upstream: upstreamName, SelectedECS: selectedECS, ECSSource: selectedSource,
		QName: qname, QType: qtype, CacheStatus: "MISS",
	})
}

func (a *App) handlePersonalDoH(w http.ResponseWriter, r *http.Request) bool {
	if isPersonalDoHPath(r.URL.Path) {
		a.handleDoH(w, r)
		return true
	}
	return false
}

func nxdomainResponse(query *dns.Msg) []byte {
	var response dns.Msg
	response.SetReply(query)
	response.Rcode = dns.RcodeNameError
	response.Authoritative = false
	packed, err := response.Pack()
	if err != nil {
		return []byte{}
	}
	return packed
}

func (a *App) blockPageResponse(ctx context.Context, ownerID string, query *dns.Msg) ([]byte, bool) {
	settings, err := a.store.getBlockSettings(ownerID)
	if err != nil || settings.Mode != "block_page" {
		return nil, false
	}
	target, ok := blockPageDNSTarget(settings.BlockPageURL)
	if !ok {
		return nil, false
	}
	return dnsRedirectResponse(ctx, query, target), true
}

func blockPageDNSTarget(rawURL string) (string, bool) {
	value := strings.TrimSpace(rawURL)
	if value == "" {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	host := parsed.Hostname()
	if parsed.Scheme == "" {
		parsed, err = url.Parse("//" + value)
		if err != nil {
			return "", false
		}
		host = parsed.Hostname()
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(host)); net.ParseIP(host) == nil && !ok {
		return "", false
	}
	return host, true
}

func dnsRedirectResponse(ctx context.Context, query *dns.Msg, target string) []byte {
	var response dns.Msg
	response.SetReply(query)
	response.Rcode = dns.RcodeSuccess
	response.Authoritative = false
	if len(query.Question) == 0 {
		packed, _ := response.Pack()
		return packed
	}
	question := query.Question[0]
	ttl := uint32(60)
	targetIP := net.ParseIP(target)
	if targetIP != nil {
		switch question.Qtype {
		case dns.TypeA:
			if ip4 := targetIP.To4(); ip4 != nil {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: question.Qclass, Ttl: ttl},
					A:   ip4,
				})
			}
		case dns.TypeAAAA:
			if ip16 := targetIP.To16(); ip16 != nil && targetIP.To4() == nil {
				response.Answer = append(response.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: question.Qclass, Ttl: ttl},
					AAAA: ip16,
				})
			}
		}
	} else {
		targetName := dns.Fqdn(target)
		response.Answer = append(response.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: question.Qclass, Ttl: ttl},
			Target: targetName,
		})
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			lookupCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
			defer cancel()
			for _, ip := range lookupRedirectTargetIPs(lookupCtx, target) {
				if question.Qtype == dns.TypeA {
					if ip4 := ip.To4(); ip4 != nil {
						response.Answer = append(response.Answer, &dns.A{
							Hdr: dns.RR_Header{Name: targetName, Rrtype: dns.TypeA, Class: question.Qclass, Ttl: ttl},
							A:   ip4,
						})
					}
					continue
				}
				if ip16 := ip.To16(); ip16 != nil && ip.To4() == nil {
					response.Answer = append(response.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: targetName, Rrtype: dns.TypeAAAA, Class: question.Qclass, Ttl: ttl},
						AAAA: ip16,
					})
				}
			}
		}
	}
	packed, err := response.Pack()
	if err != nil {
		return []byte{}
	}
	return packed
}

func lookupRedirectTargetIPs(ctx context.Context, target string) []net.IP {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", target)
	if err != nil {
		return nil
	}
	return ips
}

func isPersonalDoHPath(path string) bool {
	tail := strings.Trim(strings.TrimPrefix(path, "/api/v1/dquery/"), "/")
	return tail != "" && !strings.Contains(tail, "/") && strings.HasPrefix(tail, "usr_")
}

func personalUserIDFromPath(path string) string {
	tail := strings.Trim(strings.TrimPrefix(path, "/api/v1/dquery/"), "/")
	if tail != "" && !strings.Contains(tail, "/") && strings.HasPrefix(tail, "usr_") {
		return tail
	}
	return ""
}

func (a *App) logPersonalQuery(ownerID, qname, qtype, action, ruleSetName, clientIP string) {
	if ownerID == "" || a.store == nil {
		return
	}
	a.store.insertQueryLog(queryLog{
		ID:          "log_" + randomHex(8),
		OwnerUserID: ownerID,
		QName:       qname,
		QType:       qtype,
		Action:      action,
		RuleSetName: ruleSetName,
		ClientIP:    clientIP,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	})
}

func validateRequest(r *http.Request) error {
	if r.Method != http.MethodPost {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return fmt.Errorf("invalid content-type")
	}
	if mediaType != "application/dns-message" {
		return fmt.Errorf("content-type must be application/dns-message")
	}
	return nil
}

func (a *App) pickRoute(qname string, now time.Time) (string, config.RouteConfig) {
	if a.rules.IsCNDomain(qname, now) {
		return "cn", a.cfg.Routing.CN
	}
	return "global", a.cfg.Routing.Global
}

func (a *App) pickRouteForVisitor(qname, visitorIP, country string, now time.Time) (string, config.RouteConfig) {
	if isMainlandChinaRequest(visitorIP, country) {
		return a.pickRoute(qname, now)
	}
	return "global", a.cfg.Routing.Global
}

func isMainlandChinaRequest(visitorIP, country string) bool {
	if strings.EqualFold(strings.TrimSpace(country), "CN") {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(visitorIP))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

func (a *App) resolveWithInflight(ctx context.Context, cacheKey, routeName string, routeCfg config.RouteConfig, query *dns.Msg, queryBytes []byte, selectedECS string) (*doh.Result, string, error) {
	if cacheKey == "" {
		return a.resolveUpstream(ctx, routeName, routeCfg, query, queryBytes, selectedECS)
	}
	a.inflightMu.Lock()
	if call, ok := a.inflight[cacheKey]; ok {
		a.inflightMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, routeCfg.Upstream, ctx.Err()
		case <-call.done:
			upstreamName := routeCfg.Upstream
			if call.result != nil {
				upstreamName = call.result.UpstreamName
			}
			return call.result, upstreamName, call.err
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	a.inflight[cacheKey] = call
	a.inflightMu.Unlock()

	result, upstreamName, err := a.resolveUpstream(ctx, routeName, routeCfg, query, queryBytes, selectedECS)
	call.result, call.err = result, err
	close(call.done)
	a.inflightMu.Lock()
	delete(a.inflight, cacheKey)
	a.inflightMu.Unlock()
	return result, upstreamName, err
}

func (a *App) resolveUpstream(ctx context.Context, routeName string, routeCfg config.RouteConfig, query *dns.Msg, queryBytes []byte, selectedECS string) (*doh.Result, string, error) {
	primarySpec := a.cfg.Upstreams[routeCfg.Upstream]
	primaryCtx, cancel := context.WithTimeout(ctx, primarySpec.Timeout)
	defer cancel()
	result, err := a.resolver.Resolve(primaryCtx, routeCfg.Upstream, query, queryBytes, selectedECS)
	if err == nil {
		return result, result.UpstreamName, nil
	}
	if routeCfg.FallbackUpstream == "" {
		return nil, routeCfg.Upstream, err
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, routeCfg.Upstream, err
	}

	fallbackSpec := a.cfg.Upstreams[routeCfg.FallbackUpstream]
	log.Printf("level=warn route=%s event=primary_failed upstream=%s fallback=%s err=%v", routeName, routeCfg.Upstream, routeCfg.FallbackUpstream, err)
	fallbackCtx, fallbackCancel := context.WithTimeout(ctx, fallbackSpec.Timeout)
	defer fallbackCancel()
	result, fbErr := a.resolver.Resolve(fallbackCtx, routeCfg.FallbackUpstream, query, queryBytes, selectedECS)
	if fbErr != nil {
		return nil, routeCfg.FallbackUpstream, fbErr
	}
	return result, result.UpstreamName, nil
}

func (a *App) readQueryBytes(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		encoded := strings.TrimSpace(r.URL.Query().Get("dns"))
		if encoded == "" {
			return nil, fmt.Errorf("missing dns query parameter")
		}
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode dns parameter: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("empty dns parameter")
		}
		return data, nil
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, a.cfg.Server.MaxRequestBody))
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		if len(body) == 0 {
			return nil, fmt.Errorf("empty request body")
		}
		return body, nil
	default:
		return nil, fmt.Errorf("unsupported method")
	}
}

func (a *App) extractClientECS(r *http.Request, query *dns.Msg) (string, string) {
	if value, source := ecs.ExtractClientFromDNS(query, a.cfg.ECS.ClientV4Max, a.cfg.ECS.ClientV6Max); value != "" {
		return value, source
	}
	if a.cfg.ECS.AllowQueryECS {
		if value, ok := ecs.NormalizeExplicit(r.URL.Query().Get("ecs"), a.cfg.ECS.ClientV4Max, a.cfg.ECS.ClientV6Max); ok {
			return value, "query-ecs"
		}
	}
	if a.cfg.ECS.AllowHeaderECS {
		if value, ok := ecs.NormalizeExplicit(r.Header.Get(a.cfg.ECS.HeaderName), a.cfg.ECS.ClientV4Max, a.cfg.ECS.ClientV6Max); ok {
			return value, "header-ecs"
		}
	}
	return "", "missing"
}

func (a *App) extractClientIP(r *http.Request) string {
	if value := firstIP(r.Header.Get(a.cfg.Server.ClientIPHeader)); value != "" {
		return value
	}
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"} {
		if value := firstIP(r.Header.Get(header)); value != "" {
			return value
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func firstIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, ",") {
		value = strings.TrimSpace(strings.Split(value, ",")[0])
	}
	return value
}

type debugHeaders struct{ Route, Upstream, SelectedECS, ECSSource, QName, QType, CacheStatus string }

func (a *App) writeDNSResponse(w http.ResponseWriter, r *http.Request, status int, payload []byte, ttl time.Duration, dbg debugHeaders) {
	w.Header().Set("Content-Type", "application/dns-message")
	if dbg.Route != "" {
		w.Header().Set("X-DQuery-Route", dbg.Route)
	}
	if dbg.Upstream != "" {
		w.Header().Set("X-DQuery-Upstream", dbg.Upstream)
	}
	if dbg.SelectedECS != "" {
		w.Header().Set("X-DQuery-Selected-ECS", dbg.SelectedECS)
	}
	if dbg.ECSSource != "" {
		w.Header().Set("X-DQuery-ECS-Source", dbg.ECSSource)
	}
	if dbg.CacheStatus != "" {
		w.Header().Set("X-DQuery-Cache", dbg.CacheStatus)
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", buildCacheControl(a.cfg.Cache, ttl))
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func buildCacheControl(cfg config.CacheConfig, ttl time.Duration) string {
	maxAge := int(effectiveResponseCacheTTL(ttl, cfg).Seconds())
	sMaxAge := int(cfg.ResponseSharedMaxAge.Seconds())
	if sMaxAge <= 0 {
		sMaxAge = maxAge
	}
	swr := int(cfg.ResponseStaleWhileRevalidate.Seconds())
	sie := int(cfg.ResponseStaleIfError.Seconds())
	return fmt.Sprintf("public, max-age=%d, s-maxage=%d, stale-while-revalidate=%d, stale-if-error=%d", maxAge, sMaxAge, swr, sie)
}

func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "dqueryd")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func responseTTL(payload []byte, positive, negative, minPositive, maxPositive time.Duration) time.Duration {
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil {
		return negative
	}
	if msg.Rcode != dns.RcodeSuccess {
		return negative
	}
	minTTL := uint32(0)
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), append(msg.Ns, msg.Extra...)...) {
		if rr == nil {
			continue
		}
		ttl := rr.Header().Ttl
		if ttl > 0 && (minTTL == 0 || ttl < minTTL) {
			minTTL = ttl
		}
	}
	if minTTL == 0 {
		return clampTTL(positive, minPositive, maxPositive)
	}
	return clampTTL(time.Duration(minTTL)*time.Second, minPositive, maxPositive)
}

func clampTTL(ttl, minPositive, maxPositive time.Duration) time.Duration {
	if ttl <= 0 {
		return ttl
	}
	if minPositive > 0 && ttl < minPositive {
		ttl = minPositive
	}
	if maxPositive > 0 && ttl > maxPositive {
		ttl = maxPositive
	}
	return ttl
}

func effectiveResponseCacheTTL(ttl time.Duration, cfg config.CacheConfig) time.Duration {
	if cfg.ResponseBrowserMaxAge > 0 && ttl > cfg.ResponseBrowserMaxAge {
		return cfg.ResponseBrowserMaxAge
	}
	if ttl <= 0 {
		return cfg.DefaultPositiveTTL
	}
	return ttl
}
