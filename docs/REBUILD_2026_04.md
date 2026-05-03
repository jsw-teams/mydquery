# 2026-04 Rebuild goals

This rebuild is organized around the following requirements:

1. Keep CN primary upstream on `https://way.jsw.ac.cn/api/v1/edge-cn-rslv-7f3c/query`.
2. Use optimistic local cache (`stale-if-error`) so CN timeout / 502 events can return recently-good answers.
3. Switch Global primary upstream to `https://dni9tppp7v.cloudflare-gateway.com/dns-query`.
4. Keep a Global fallback (`google_global`) for cold-query rescue.
5. Support ECH/HTTPS records by proxying `HTTPS` / `SVCB` responses as-is and caching them independently from `A` / `AAAA`.
6. Keep CN learning in `all_answers_cn` mode; only `A` / `AAAA` answers participate in CN learning.

## Notes

- Optimistic cache helps hot domains survive upstream instability, but it does not fix first-query cold misses.
- `selfhosted_cn_1` is configured as `GET` + `http_version: h1` to reduce ESA header wait issues.
- `alidns_cn` remains configured as CN fallback.
