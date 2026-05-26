package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"gateway-dquery-go/internal/config"
)

func TestDNSCacheKeyNormalizesQueryIDCaseAndPadding(t *testing.T) {
	first := newTestQuery(100, "Example.COM.", dns.TypeA)
	second := newTestQuery(200, "example.com.", dns.TypeA)
	addPadding(second)

	firstKey := dnsCacheKey("global", "cloudflare", "", first)
	secondKey := dnsCacheKey("global", "cloudflare", "", second)
	if firstKey != secondKey {
		t.Fatalf("expected equivalent DNS queries to share cache key, got %q and %q", firstKey, secondKey)
	}

	otherType := newTestQuery(100, "example.com.", dns.TypeAAAA)
	if firstKey == dnsCacheKey("global", "cloudflare", "", otherType) {
		t.Fatal("expected qtype to be part of cache key")
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
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dquery?dns="+encoded, nil)

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
