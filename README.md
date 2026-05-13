# dquery

`dquery` is the JS.Gripe DNS query service for `dns.js.gripe` and the DoH API behind `gateway.js.gripe/api/v1/dquery`.

Current production shape:

- Backend: Go service `dqueryd`
- Public API: DNS-over-HTTPS wire format
- Frontend: Astro static site
- Routing: ChinaMax domain rules plus visitor-aware global routing
- Storage: SQLite for account-owned DNS profiles, rules, tokens, and logs
- Identity: account-system is the source of user identity
- Reverse proxy: OpenResty on `gateway.js.gripe` and `dns.js.gripe`

## Behavior

Public DNS queries remain anonymous. Account-system integration is used for the personal DNS console and future per-user rules.

Routing rules:

- Requests from mainland China keep the China optimization path.
- Requests outside mainland China use the global route and attach visitor ECS when possible, so upstream answers match the visitor location.
- The frontend displays response metadata returned by the API: route, upstream, ECS, ECS source, and cache status.

Important response headers:

```text
X-DQuery-Route
X-DQuery-Upstream
X-DQuery-Selected-ECS
X-DQuery-ECS-Source
X-DQuery-Cache
```

OpenResty exposes those headers to `https://dns.js.gripe` with CORS.

## Main Paths

```text
cmd/dqueryd/                 Go service entrypoint
cmd/chinamax-build/          ChinaMax compact rule builder
internal/server/             DoH API, routing, account-owned DNS data
internal/doh/                Upstream DoH client
internal/ecs/                ECS extraction and injection
internal/chinarules/         ChinaMax matching and CN learning
frontend/                    Astro frontend
configs/config.public.yaml   Production-style service config
configs/account.integration.example.yaml
```

## Configuration

Production service config is YAML. The running systemd service starts `dqueryd` with:

```text
/opt/dquery/bin/dqueryd -config /etc/dqueryd/config.yaml
```

So the live configuration file is:

```text
/etc/dqueryd/config.yaml
```

The public example is:

```text
configs/config.public.yaml
```

Key fields:

- `server.client_ip_header`: normally `CF-Connecting-IP`
- `china_rules.compact_json_path`: compact ChinaMax rules file
- `routing.cn`: China route and upstream
- `routing.global`: global route and upstream
- `ecs.*`: visitor/client ECS masks and optional explicit ECS controls
- `cache.*`: DNS and HTTP cache policy
- `account.base_url`: account-system API base URL
- `storage.db_path`: SQLite database path
- `upstreams.*.max_concurrent`: upstream concurrency cap

Account-system client registration values are documented in:

```text
configs/account.integration.example.yaml
```

Create a client in account-system with:

- application name: `dquery`
- redirect URI: `https://dns.js.gripe/auth/account/callback`
- scopes: `accounts:read`, `identities:resolve`, `identities:link`

Save the returned `client_id` and one-time API key in deployment secrets/config. Do not treat the application name as the client id.

Example account block for `/etc/dqueryd/config.yaml`:

```yaml
account:
  enabled: true
  client_name: dquery
  client_id: "cli_xxx"
  api_key: "account-system-one-time-apikey"
  base_url: "http://127.0.0.1:9100/api/v1/myaccount"
  login_url: "https://account.js.gripe/login"
  redirect_uri: "https://dns.js.gripe/auth/account/callback"
  scopes:
    - accounts:read
    - identities:resolve
    - identities:link
```

`dqueryd` uses `account.enabled` and `account.base_url` for account session verification. It also exposes a public, no-secret login configuration endpoint at `/api/v1/dquery/account/client`; the static login page reads `client_id`, `login_url`, `redirect_uri`, and `scopes` from that endpoint so production can rotate account-system client values from `/etc/dqueryd/config.yaml` without rebuilding the frontend. `api_key` remains server-side only and is never returned by that endpoint.

## Frontend DNS JSON

The public query UI parses DNS wire responses in the browser. Structured RDATA is decoded into readable DNS JSON-style values for common records, including `A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `TXT`, `SOA`, `SRV`, `CAA`, `HTTPS`/`SVCB`, `DS`, and `DNSKEY`. Unknown record types fall back to hexadecimal RDATA.

## Build

Backend:

```bash
cd /opt/dquery
go test ./...
go build -buildvcs=false -o /opt/dquery/bin/dqueryd ./cmd/dqueryd
go build -buildvcs=false -o /opt/dquery/bin/chinamax-build ./cmd/chinamax-build
```

Frontend:

```bash
cd /opt/dquery/frontend
npm run build
```

## ChinaMax Rules

```bash
/opt/dquery/bin/chinamax-build \
  -src /opt/dquery/vendor/ChinaMax_Classical.yaml \
  -include /opt/dquery/data/local-include.txt \
  -exclude /opt/dquery/data/local-exclude.txt \
  -out /var/lib/dqueryd/chinamax_classical.compact.json
```

## Deploy

The production service runs as:

```bash
systemctl status dqueryd.service
journalctl -u dqueryd.service -f
```

After backend changes:

```bash
go build -buildvcs=false -o /tmp/dqueryd ./cmd/dqueryd
sudo install -m 0755 -o dqueryd -g dqueryd /tmp/dqueryd /opt/dquery/bin/dqueryd
sudo systemctl restart dqueryd.service
```

After OpenResty changes:

```bash
sudo openresty -t
sudo openresty -s reload
```

## Verification

Health:

```bash
curl https://gateway.js.gripe/api/v1/dquery/healthz
```

Simulate global visitor routing:

```bash
curl -k --resolve gateway.js.gripe:443:127.0.0.1 \
  -D - -o /tmp/dquery.dns \
  -H 'CF-IPCountry: US' \
  -H 'CF-Connecting-IP: 8.8.8.8' \
  'https://gateway.js.gripe/api/v1/dquery?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'
```

Expected headers include:

```text
X-DQuery-Route: global
X-DQuery-ECS-Source: visitor
X-DQuery-Selected-ECS: 8.8.8.0/24
```
