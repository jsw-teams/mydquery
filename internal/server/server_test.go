package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
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

func TestQueryLogStatsReturnsTopQueriedAndBlockedDomains(t *testing.T) {
	store, err := newAccountStore(filepath.Join(t.TempDir(), "dquery.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.db.Close() })

	for _, entry := range []queryLog{
		{ID: "1", OwnerUserID: "user_1", QName: "ads.example.com", QType: "A", Action: "block_domain_rule", CreatedAt: "2026-05-25T00:00:00Z"},
		{ID: "2", OwnerUserID: "user_1", QName: "ads.example.com", QType: "AAAA", Action: "block_ruleset", CreatedAt: "2026-05-25T00:00:01Z"},
		{ID: "3", OwnerUserID: "user_1", QName: "api.example.com", QType: "A", Action: "resolve", CreatedAt: "2026-05-25T00:00:02Z"},
		{ID: "4", OwnerUserID: "user_2", QName: "ads.example.com", QType: "A", Action: "block_domain_rule", CreatedAt: "2026-05-25T00:00:03Z"},
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
