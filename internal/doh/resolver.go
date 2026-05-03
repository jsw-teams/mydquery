package doh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"

	"gateway-dquery-go/internal/config"
	"gateway-dquery-go/internal/ecs"
)

const maxDNSResponseSize = 1 << 20

type Result struct {
	UpstreamName  string
	ResponseBytes []byte
}

type upstreamClient struct {
	spec   config.UpstreamSpec
	client *http.Client
}

type Resolver struct {
	upstreams map[string]upstreamClient
}

func NewResolver(upstreams map[string]config.UpstreamSpec) *Resolver {
	resolver := &Resolver{upstreams: make(map[string]upstreamClient, len(upstreams))}
	for name, spec := range upstreams {
		resolver.upstreams[name] = upstreamClient{spec: spec, client: newHTTPClient(spec)}
	}
	return resolver
}

func newHTTPClient(spec config.UpstreamSpec) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: spec.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if strings.EqualFold(strings.TrimSpace(spec.HTTPVersion), "h1") {
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: transport}
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

func buildPayload(query *dns.Msg, queryBytes []byte, selectedECS string) ([]byte, error) {
	if strings.TrimSpace(selectedECS) == "" && len(queryBytes) > 0 {
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
