package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

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
	startedAt time.Time

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall
}

func New(cfg *config.Config, rules *chinarules.Store, resolver *doh.Resolver) *App {
	var c *cache.Cache
	if cfg.Cache.Enabled {
		c = cache.New(cfg.Cache.MaxItems)
	}
	return &App{
		cfg:       cfg,
		rules:     rules,
		resolver:  resolver,
		cache:     c,
		startedAt: time.Now().UTC(),
		inflight:  map[string]*inflightCall{},
	}
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/dquery", a.handleDoH)
	mux.HandleFunc("/api/v1/dquery/", a.handleSubpath)
	mux.HandleFunc("/api/v1/dquery/healthz", a.handleHealthz)
	mux.HandleFunc("/api/v1/dquery/readyz", a.handleReadyz)
	return withCommonHeaders(mux)
}

func (a *App) handleSubpath(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/dquery/healthz":
		a.handleHealthz(w, r)
	case "/api/v1/dquery/readyz":
		a.handleReadyz(w, r)
	case "/api/v1/dquery/":
		a.handleDoH(w, r)
	default:
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

func (a *App) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/dquery" && r.URL.Path != "/api/v1/dquery/" {
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

	visitorIP := a.extractClientIP(r)
	visitorECS, visitorPresent := ecs.VisitorFromIP(visitorIP, a.cfg.ECS.VisitorV4Mask, a.cfg.ECS.VisitorV6Mask)
	if !visitorPresent {
		visitorECS = ""
	}
	clientECS, _ := a.extractClientECS(r, &query)
	routeName, routeCfg := a.pickRoute(qname, time.Now())
	selectedECS, selectedSource := ecs.Select(routeCfg.ECSSource, ecs.Candidates{Visitor: visitorECS, Client: clientECS})

	cacheKey := ""
	if a.cache != nil {
		cacheKey = cache.Key(routeName, routeCfg.Upstream, selectedECS, string(queryBytes))
		if cached, ok := a.cache.GetFresh(cacheKey, time.Now()); ok {
			ttl := responseTTL(cached, a.cfg.Cache.DefaultPositiveTTL, a.cfg.Cache.NegativeTTL, a.cfg.Cache.MinPositiveTTL, a.cfg.Cache.MaxPositiveTTL)
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
	a.writeDNSResponse(w, r, http.StatusOK, result.ResponseBytes, effectiveResponseCacheTTL(ttl, a.cfg.Cache), debugHeaders{
		Route: routeName, Upstream: upstreamName, SelectedECS: selectedECS, ECSSource: selectedSource,
		QName: qname, QType: qtype, CacheStatus: "MISS",
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
	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", buildCacheControl(a.cfg.Cache, ttl))
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	if a.cfg.Routing.DebugResponseHeaders {
		w.Header().Set("X-DQuery-Cache", dbg.CacheStatus)
		w.Header().Set("X-DQuery-Route", dbg.Route)
		w.Header().Set("X-DQuery-Upstream", dbg.Upstream)
		w.Header().Set("X-DQuery-QName", dbg.QName)
		w.Header().Set("X-DQuery-QType", dbg.QType)
		w.Header().Set("X-DQuery-ECS", dbg.SelectedECS)
		w.Header().Set("X-DQuery-ECS-Source", dbg.ECSSource)
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
		w.Header().Set("X-Content-Type-Options", "nosniff")
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
