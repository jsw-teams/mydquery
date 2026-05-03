# Cloudflare API Shield usage notes for dquery

1. Upload `api-shield-dquery-openapi.yaml` to API Shield Schema validation.
2. Start with **Log** action first, then move to **Block** after confirming clients only use:
   - `GET /api/v1/dquery?dns=...`
   - `POST /api/v1/dquery` with `Content-Type: application/dns-message`
3. Add `/api/v1/dquery/healthz` and `/api/v1/dquery/readyz` to Endpoint Management if you want them tracked.
4. Pair Schema validation with WAF custom rules:
   - only allow `GET` and `POST` for `/api/v1/dquery*`
   - only allow `GET` on `/api/v1/dquery/healthz` and `/api/v1/dquery/readyz`
   - optionally rate limit `/api/v1/dquery*`
5. If your Cloudflare account has API Shield JWT validation entitlement, reserve JWT for private management paths only. Public DoH clients like OpenClash generally should not be forced to present JWTs.
6. If you control a small set of clients and those clients support client certificates, you can also evaluate API Shield mTLS at the Cloudflare edge.
