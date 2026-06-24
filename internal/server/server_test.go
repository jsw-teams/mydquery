package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"gateway-dquery-go/internal/chinarules"
	"gateway-dquery-go/internal/config"
)

func TestDNSCacheKeyNormalizesQueryIDCaseAndPadding(t *testing.T) {
	first := newTestQuery(100, "Example.COM.", dns.TypeA)
	second := newTestQuery(200, "example.com.", dns.TypeA)
	addPadding(second)

	firstKey := dnsCacheKey("public", "global", "cloudflare", "", first)
	secondKey := dnsCacheKey("public", "global", "cloudflare", "", second)
	if firstKey != secondKey {
		t.Fatalf("expected equivalent DNS queries to share cache key, got %q and %q", firstKey, secondKey)
	}

	otherType := newTestQuery(100, "example.com.", dns.TypeAAAA)
	if firstKey == dnsCacheKey("public", "global", "cloudflare", "", otherType) {
		t.Fatal("expected qtype to be part of cache key")
	}
}

func TestResolverDoHPathRequiresUUIDAndDnsQuerySuffix(t *testing.T) {
	valid := "/dns-query/550e8400-e29b-41d4-a716-446655440000"
	if !isResolverDoHPath(valid) {
		t.Fatal("expected UUID resolver DoH path to be accepted")
	}
	if got := resolverUUIDFromPath(valid); got != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("unexpected resolver uuid %q", got)
	}
	for _, path := range []string{"/usr_abc/dns-query", "/api/v1/dquery/usr_abc", "/550e8400-e29b-41d4-a716-446655440000", "/550e8400-e29b-41d4-a716-446655440000/dns-query", "/dns-query"} {
		if isResolverDoHPath(path) {
			t.Fatalf("expected %s not to be treated as resolver DoH", path)
		}
	}
}

func TestAnonymousDNSQueryRegionalPolicyBlocksCNHKAndMO(t *testing.T) {
	app := &App{cfg: &config.Config{RegionalPolicy: config.RegionalPolicyConfig{
		Enabled:             true,
		ClientCountryHeader: "CF-IPCountry",
		AnonymousDNSQuery: config.AnonymousDNSQueryPolicy{
			BlockedCountries: []string{"CN", "HK", "MO"},
			StatusCode:       http.StatusUnavailableForLegalReasons,
			Reason:           "anonymous_doh_unavailable_in_region",
			BodyMessage:      "blocked",
		},
	}}}
	for _, country := range []string{"CN", "HK", "MO"} {
		req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
		req.Header.Set("CF-IPCountry", country)
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnavailableForLegalReasons {
			t.Fatalf("expected %s to be blocked with 451, got %d", country, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("expected 451 cache-control no-store, got %q", got)
		}
	}
}

func TestFrontendLookupIgnoresRegionalPolicyBeforeInitialization(t *testing.T) {
	app := &App{cfg: &config.Config{RegionalPolicy: config.RegionalPolicyConfig{
		Enabled:             true,
		ClientCountryHeader: "CF-IPCountry",
		AnonymousDNSQuery: config.AnonymousDNSQueryPolicy{
			BlockedCountries: []string{"CN", "HK", "MO"},
			StatusCode:       http.StatusUnavailableForLegalReasons,
			Reason:           "anonymous_doh_unavailable_in_region",
			BodyMessage:      "blocked",
		},
	}}}
	for _, country := range []string{"CN", "HK", "MO"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/dquery/lookup", nil)
		req.Header.Set("CF-IPCountry", country)
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		if rec.Code == http.StatusUnavailableForLegalReasons {
			t.Fatalf("expected frontend lookup path to ignore regional policy for %s", country)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected uninitialized frontend lookup without dns payload to reach request validation, got %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestSetupInitCreatesLocalSystemAdminAndSession(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dquery/setup/status", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"initialized":false`) {
		t.Fatalf("expected uninitialized setup status, got %d %s", rec.Code, rec.Body.String())
	}

	body := strings.NewReader(`{"email":"admin@example.com","display_name":"Admin","password":"ChangeMe123!"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/dquery/setup/init", body)
	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected setup init 201, got %d %s", rec.Code, rec.Body.String())
	}
	if cookie := rec.Result().Cookies(); len(cookie) == 0 || cookie[0].Name != "dquery_session" {
		t.Fatalf("expected setup init to create dquery_session cookie, got %#v", cookie)
	}

	var count int
	if err := app.store.db.QueryRow(`SELECT COUNT(1) FROM dquery_users WHERE role = 'system_admin'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected one system admin, count=%d err=%v", count, err)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/dquery/setup/init", strings.NewReader(`{"email":"again@example.com","password":"ChangeMe123!"}`))
	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected duplicate setup init 409, got %d", rec.Code)
	}
}

func TestLocalLoginAndAuthMeUseLocalSessionCookie(t *testing.T) {
	app := newTestApp(t)
	user, err := app.store.createLocalUser("admin@example.com", "Admin", "system_admin", "ChangeMe123!")
	if err != nil {
		t.Fatal(err)
	}
	app.store.ensureDefaultProfile(user)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dquery/auth/me", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth/me without cookie 401, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/dquery/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"ChangeMe123!"}`))
	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected local login 200, got %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie from local login")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/dquery/auth/me", nil)
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected auth/me with cookie 200, got %d %s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	gotUser := payload["user"].(map[string]any)
	if gotUser["id"] != user.ID {
		t.Fatalf("expected local user id %s, got %#v", user.ID, gotUser["id"])
	}
}

func TestDNSQueryOptionsReturnsCORSForDQueryOrigin(t *testing.T) {
	app := &App{cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodOptions, "/dns-query", nil)
	req.Header.Set("Origin", "https://dquery.js.gripe")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected OPTIONS to return 204, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dquery.js.gripe" {
		t.Fatalf("unexpected allow-origin %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Fatalf("expected POST in allow-methods, got %q", got)
	}
}

func newTestApp(t *testing.T) *App {
	t.Helper()
	store, err := newAccountStore(filepath.Join(t.TempDir(), "dquery.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.db.Close() })
	return &App{cfg: &config.Config{}, store: store}
}

func TestCacheNamespaceIncludesResolverUUID(t *testing.T) {
	query := newTestQuery(100, "example.com.", dns.TypeA)
	publicKey := dnsCacheKey(cacheNamespace(""), "global", "cloudflare", "", query)
	resolverKey := dnsCacheKey(cacheNamespace("550e8400-e29b-41d4-a716-446655440000"), "global", "cloudflare", "", query)
	if publicKey == resolverKey {
		t.Fatal("expected resolver UUID to separate cache namespace")
	}
}

func TestResponseWithQueryIDRewritesCachedResponseID(t *testing.T) {
	response := new(dns.Msg)
	response.SetReply(newTestQuery(100, "example.com.", dns.TypeA))
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}

	rewritten := responseWithQueryID(payload, 200)
	var decoded dns.Msg
	if err := decoded.Unpack(rewritten); err != nil {
		t.Fatal(err)
	}
	if decoded.Id != 200 {
		t.Fatalf("expected cached response id to be rewritten to 200, got %d", decoded.Id)
	}
}

func TestReadQueryBytesAcceptsPaddedGETParam(t *testing.T) {
	query := newTestQuery(100, "example.com.", dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.URLEncoding.EncodeToString(payload)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)

	app := &App{}
	got, err := app.readQueryBytes(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("decoded query payload did not match original")
	}
}

func TestCloudflareEdgeIPIsNotUsedAsVisitorECS(t *testing.T) {
	if !isCloudflareEdgeIP("172.69.234.1") {
		t.Fatal("expected 172.69.234.1 to be detected as Cloudflare edge")
	}
	if isCloudflareEdgeIP("8.8.8.8") {
		t.Fatal("expected ordinary public resolver IP not to be detected as Cloudflare edge")
	}
}

func TestMainlandVisitorUsesChinaRulesForRouting(t *testing.T) {
	rulePath := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(rulePath, []byte(`{
		"source": "test",
		"exacts": [],
		"suffixes": [],
		"keywords": [],
		"cidr_v4": [],
		"cidr_v6": []
	}`), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := chinarules.Load(rulePath)
	if err != nil {
		t.Fatal(err)
	}

	app := &App{
		cfg: &config.Config{Routing: config.RoutingConfig{
			CN:     config.RouteConfig{Upstream: "alidns_cn_public"},
			Global: config.RouteConfig{Upstream: "cloudflare_gateway_global"},
		}},
		rules: rules,
	}

	for _, visitorIP := range []string{"223.5.5.5", "112.5.241.88", "39.144.252.248", "2409:8934:4cf4:c066:e80d:dd66:311f:2687"} {
		routeName, routeCfg := app.pickRouteForVisitor("example.com.", visitorIP, "", time.Now())
		if routeName != "global" || routeCfg.Upstream != "cloudflare_gateway_global" {
			t.Fatalf("expected mainland visitor %s to use global route for generic domain, got route=%q upstream=%q", visitorIP, routeName, routeCfg.Upstream)
		}
	}
}

func TestResponseTTLUsesAnswerTTLWithoutPositiveFloor(t *testing.T) {
	response := new(dns.Msg)
	response.SetReply(newTestQuery(100, "short.example.", dns.TypeA))
	response.Answer = append(response.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "short.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 12},
		A:   []byte{192, 0, 2, 10},
	})
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ttl := responseTTL(payload, 300*time.Second, 60*time.Second, 60*time.Second, 1800*time.Second)
	if ttl != 12*time.Second {
		t.Fatalf("expected answer TTL to win without min-positive floor, got %s", ttl)
	}
}

func TestResponseTTLUsesSOAForNegativeResponses(t *testing.T) {
	response := new(dns.Msg)
	response.SetReply(newTestQuery(100, "missing.example.", dns.TypeA))
	response.Rcode = dns.RcodeNameError
	response.Ns = append(response.Ns, &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120},
		Ns:      "ns.example.",
		Mbox:    "hostmaster.example.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  30,
	})
	payload, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ttl := responseTTL(payload, 300*time.Second, 60*time.Second, 60*time.Second, 1800*time.Second)
	if ttl != 30*time.Second {
		t.Fatalf("expected negative TTL from SOA minimum, got %s", ttl)
	}
	if stale := cacheStaleExtra(payload, zeroCacheConfig()); stale != 0 {
		t.Fatalf("expected negative response not to get stale-if-error, got %s", stale)
	}
}

func TestQueryLogStatsReturnsTopQueriedAndBlockedDomains(t *testing.T) {
	store, err := newAccountStore(filepath.Join(t.TempDir(), "dquery.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.db.Close() })

	now := time.Now().UTC()
	for _, entry := range []queryLog{
		{ID: "1", OwnerUserID: "user_1", QName: "ads.example.com", QType: "A", Action: "block_domain_rule", CreatedAt: now.Format(time.RFC3339)},
		{ID: "2", OwnerUserID: "user_1", QName: "ads.example.com", QType: "AAAA", Action: "block_ruleset", CreatedAt: now.Add(time.Second).Format(time.RFC3339)},
		{ID: "3", OwnerUserID: "user_1", QName: "api.example.com", QType: "A", Action: "resolve", CreatedAt: now.Add(2 * time.Second).Format(time.RFC3339)},
		{ID: "4", OwnerUserID: "user_2", QName: "ads.example.com", QType: "A", Action: "block_domain_rule", CreatedAt: now.Add(3 * time.Second).Format(time.RFC3339)},
	} {
		store.insertQueryLog(entry)
	}

	stats, err := store.queryLogStats("user_1", "5")
	if err != nil {
		t.Fatal(err)
	}
	if got := stats["queried"][0]; got.Domain != "ads.example.com" || got.Count != 2 {
		t.Fatalf("unexpected top queried domain: %#v", got)
	}
	if got := stats["blocked"][0]; got.Domain != "ads.example.com" || got.Count != 2 {
		t.Fatalf("unexpected top blocked domain: %#v", got)
	}
	if len(stats["blocked"]) != 1 {
		t.Fatalf("expected only blocked domains in blocked chart, got %#v", stats["blocked"])
	}
}

func zeroCacheConfig() config.CacheConfig {
	return config.CacheConfig{}
}

func newTestQuery(id uint16, name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.Id = id
	return msg
}

func addPadding(msg *dns.Msg) {
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: []byte{0, 0, 0, 0}})
	msg.Extra = append(msg.Extra, opt)
}
