package doh

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	xproxy "golang.org/x/net/proxy"

	"gateway-dquery-go/internal/config"
	"gateway-dquery-go/internal/ecs"
)

const maxDNSResponseSize = 1 << 20

type Result struct {
	UpstreamName  string
	ResponseBytes []byte
}

type upstreamClient struct {
	spec       config.UpstreamSpec
	client     *http.Client
	signer     *dqueryHMACSigner
	concurrent chan struct{}
}

type Resolver struct {
	upstreams map[string]upstreamClient
}

func NewResolver(upstreams map[string]config.UpstreamSpec) *Resolver {
	resolver := &Resolver{upstreams: make(map[string]upstreamClient, len(upstreams))}
	for name, spec := range upstreams {
		resolver.upstreams[name] = upstreamClient{
			spec:       spec,
			client:     newHTTPClient(spec),
			signer:     newDQueryHMACSigner(spec.HMAC),
			concurrent: newConcurrencyGate(spec.MaxConcurrent),
		}
	}
	return resolver
}

func newConcurrencyGate(maxConcurrent int) chan struct{} {
	if maxConcurrent <= 0 {
		return nil
	}
	return make(chan struct{}, maxConcurrent)
}

func newHTTPClient(spec config.UpstreamSpec) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       spec.MaxConcurrent,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: spec.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if proxyURL := normalizeOutboundProxy(spec.OutboundProxy); proxyURL != "" {
		if strings.HasPrefix(proxyURL, "socks5://") || strings.HasPrefix(proxyURL, "socks5h://") {
			if proxyDialer, err := newSOCKS5ContextDialer(proxyURL, dialer); err == nil {
				transport.Proxy = nil
				transport.DialContext = proxyDialer.DialContext
			} else {
				transport.Proxy = nil
				transport.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, err }
			}
		} else if u, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		} else {
			transport.Proxy = func(*http.Request) (*url.URL, error) { return nil, err }
		}
	}
	if strings.EqualFold(strings.TrimSpace(spec.HTTPVersion), "h1") {
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: transport}
}

func normalizeOutboundProxy(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if !strings.Contains(value, "://") {
		value = "socks5h://" + value
	}
	schemeEnd := strings.Index(value, "://") + 3
	return strings.ToLower(value[:schemeEnd]) + value[schemeEnd:]
}

func newSOCKS5ContextDialer(raw string, forward *net.Dialer) (xproxy.ContextDialer, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	auth := (*xproxy.Auth)(nil)
	if u.User != nil {
		password, _ := u.User.Password()
		auth = &xproxy.Auth{User: u.User.Username(), Password: password}
	}
	dialer, err := xproxy.SOCKS5("tcp", u.Host, auth, forward)
	if err != nil {
		return nil, err
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks5 dialer does not support context")
	}
	return contextDialer, nil
}

func (r *Resolver) Resolve(ctx context.Context, upstreamName string, query *dns.Msg, queryBytes []byte, selectedECS string) (*Result, error) {
	upstream, ok := r.upstreams[upstreamName]
	if !ok {
		return nil, fmt.Errorf("upstream %q not found", upstreamName)
	}

	switch upstream.spec.Type {
	case "", "doh_wire":
		return r.resolveDoHWire(ctx, upstreamName, upstream, query, queryBytes, selectedECS)
	default:
		return nil, fmt.Errorf("unsupported upstream type %q", upstream.spec.Type)
	}
}

func (r *Resolver) resolveDoHWire(ctx context.Context, upstreamName string, upstream upstreamClient, query *dns.Msg, queryBytes []byte, selectedECS string) (*Result, error) {
	payload, err := buildPayload(query, queryBytes, selectedECS)
	if err != nil {
		return nil, err
	}
	if release, err := acquireUpstreamSlot(ctx, upstream.concurrent); err != nil {
		return nil, err
	} else {
		defer release()
	}

	method := strings.ToUpper(strings.TrimSpace(upstream.spec.Method))
	if method == "" {
		method = http.MethodPost
	}

	req, err := buildRequest(ctx, upstream.spec, method, payload)
	if err != nil {
		return nil, err
	}
	for k, v := range upstream.spec.Headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	if upstream.signer != nil {
		if err := upstream.signer.Sign(req, payload); err != nil {
			return nil, fmt.Errorf("sign upstream request: %w", err)
		}
	}

	resp, err := upstream.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read upstream response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty upstream response")
	}
	return &Result{UpstreamName: upstreamName, ResponseBytes: body}, nil
}

func acquireUpstreamSlot(ctx context.Context, gate chan struct{}) (func(), error) {
	if gate == nil {
		return func() {}, nil
	}
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for upstream concurrency slot: %w", ctx.Err())
	}
}

func buildPayload(query *dns.Msg, queryBytes []byte, selectedECS string) ([]byte, error) {
	if strings.TrimSpace(selectedECS) == "" && len(queryBytes) > 0 && !hasEDNS0Subnet(query) {
		return queryBytes, nil
	}
	outbound, err := ecs.ApplyToMessage(query, selectedECS)
	if err != nil {
		return nil, fmt.Errorf("apply ecs: %w", err)
	}
	payload, err := outbound.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}
	return payload, nil
}

func buildRequest(ctx context.Context, spec config.UpstreamSpec, method string, payload []byte) (*http.Request, error) {
	switch method {
	case http.MethodGet:
		u, err := url.Parse(spec.URL)
		if err != nil {
			return nil, fmt.Errorf("parse upstream url: %w", err)
		}
		q := u.Query()
		q.Set("dns", base64.RawURLEncoding.EncodeToString(payload))
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/dns-message")
		return req, nil
	case http.MethodPost:
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, spec.URL, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Content-Type", "application/dns-message")
		return req, nil
	default:
		return nil, fmt.Errorf("unsupported upstream method %q", method)
	}
}

func hasEDNS0Subnet(query *dns.Msg) bool {
	opt := query.IsEdns0()
	if opt == nil {
		return false
	}
	for _, item := range opt.Option {
		if _, ok := item.(*dns.EDNS0_SUBNET); ok {
			return true
		}
	}
	return false
}

type dqueryHMACSigner struct {
	keyID  string
	secret string
}

func newDQueryHMACSigner(spec config.UpstreamHMACSpec) *dqueryHMACSigner {
	if !spec.Enabled {
		return nil
	}
	keyID := strings.TrimSpace(spec.KeyID)
	if keyID == "" {
		keyID = strings.TrimSpace(os.Getenv("DQUERY_KEY_ID"))
	}
	if keyID == "" {
		keyID = "default"
	}
	secret := spec.Secret
	if strings.TrimSpace(secret) == "" {
		envName := strings.TrimSpace(spec.SecretEnv)
		if envName == "" {
			envName = "DQUERY_HMAC_SECRET"
		}
		secret = os.Getenv(envName)
	}
	return &dqueryHMACSigner{keyID: keyID, secret: secret}
}

func (s *dqueryHMACSigner) Sign(req *http.Request, body []byte) error {
	if len(s.secret) < 32 {
		return fmt.Errorf("DQUERY_HMAC_SECRET must be at least 32 characters")
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonce, err := randomBase64URL(18)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	canonical := strings.Join([]string{
		"DQUERY-HMAC-SHA256",
		strings.ToUpper(req.Method),
		strings.ToLower(req.URL.Host),
		req.URL.Path,
		ts,
		nonce,
		bodyHash,
	}, "\n")

	mac := hmac.New(sha256.New, []byte(s.secret))
	_, _ = mac.Write([]byte(canonical))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-DQuery-Key-Id", s.keyID)
	req.Header.Set("X-DQuery-Timestamp", ts)
	req.Header.Set("X-DQuery-Nonce", nonce)
	req.Header.Set("X-DQuery-Content-SHA256", bodyHash)
	req.Header.Set("X-DQuery-Signature", "v1="+sig)
	return nil
}

func randomBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
