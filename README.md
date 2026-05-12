# gateway-dquery-go (refactored rebuild)

这是一个面向 `gateway.js.gripe` 的 Go 版 DoH 分流网关。

## 这次重构做了什么

- 重写缓存为真正的 LRU，避免旧版 `order` 切片增长。
- 上游 `http.Client` / `Transport` 按 upstream 复用，不再每次查询新建连接池。
- 新增更干净的请求校验：POST 只接受 `application/dns-message`。
- 主服务支持 `SIGINT` / `SIGTERM` 优雅退出。
- `healthz` / `readyz` 返回更多运行状态，方便探活与排障。
- 修正 `chinamax-build` 对本地 include / exclude 规则的归一化处理。
- 按“不考虑旧兼容”的方向整理源码和部署材料。

## 项目结构

- `cmd/dqueryd`：主服务
- `cmd/chinamax-build`：ChinaMax 规则压缩构建器
- `internal/server`：HTTP API / 路由 / 回退 / 缓存接入
- `internal/doh`：上游 DoH 请求发送
- `internal/chinarules`：CN 域名与 CN IP 判定、动态学习
- `internal/ecs`：ECS 解析与注入
- `internal/cache`：本地 LRU 缓存
- `frontend`：Astro 静态前端，默认部署到 `dns.js.gripe`
- `deploy/openresty`：OpenResty 反代片段
- `deploy/systemd`：systemd 服务文件
- `DEPLOY_VPS.md`：VPS 覆盖式部署说明
- `REPLACE_AND_ROLLBACK.md`：替换、清理、回滚步骤

## 编译

```bash
cd /opt/dquery
go mod tidy

go build -trimpath -ldflags="-s -w" -o /opt/dquery/bin/dqueryd ./cmd/dqueryd
go build -trimpath -ldflags="-s -w" -o /opt/dquery/bin/chinamax-build ./cmd/chinamax-build
```

## 前端

静态前端基于 Astro，公网页面部署到：

- `https://dns.js.gripe`
- 查询端点：`https://gateway.js.gripe/api/v1/dquery`
- 公共分流配置：`configs/config.public.yaml`
  - 中国域名：`https://my.jsw.ac.cn/api/v1/dquery-cn`
  - 其他域名：`https://gyvpces7ig.cloudflare-gateway.com/dns-query`

```bash
cd /opt/dquery/frontend
npm ci
npm run build
```

部署到 `/var/www/dqueryd/current`：

```bash
/opt/dquery/deploy/deploy-dqueryd-frontend.sh
```

OpenResty 可使用 `deploy/openresty/dns.js.gripe.conf` 提供 `dns.js.gripe` 静态站点；`gateway.js.gripe` 继续保留 `/api/v1/dquery` 反代到本机 `127.0.0.1:18053`。

## Account center integration

`dquery` now includes an account-center client and a probe endpoint:

```bash
curl https://gateway.js.gripe/api/v1/dquery/account/me \
  -H "Authorization: Bearer <account-token>"
```

The returned `resource_owner_id` is the account-center `user.id`. Future personal DNS profiles, rules, upstream choices, and profile tokens should all be owned by this ID.

Enable it in config:

```yaml
account:
  enabled: true
  base_url: https://gateway.js.gripe/api/v1/myaccount
```

The full vNext rebuild plan is documented in `docs/ACCOUNT_REBUILD_PLAN.md`.

Account center was rebuilt in May 2026 with a separate `/login` login page, `/dashboard` account console, and role-based capabilities (`system_admin`, `operator`, `auditor`, `member`). For dquery vNext, keep account center responsible for identity and API credential registration only; dquery should create per-user DNS profiles from the returned `user.id` after first login. If old account-center data is deleted during redeploy, do not reuse legacy local IDs or email addresses as owners.

## 构建 ChinaMax 紧凑规则

```bash
/opt/dquery/bin/chinamax-build   -src /opt/dquery/vendor/ChinaMax_Classical.yaml   -include /opt/dquery/data/local-include.txt   -exclude /opt/dquery/data/local-exclude.txt   -out /var/lib/dqueryd/chinamax_classical.compact.json
```

## 说明

这份包默认维持：

- CN 主上游：`alidns_cn_public`，通过 `https://my.jsw.ac.cn/api/v1/dquery-cn` 转发
- CN 回退：空，避免额外上游链路开销
- Global 主上游：`cloudflare_gateway_global`
- Global 回退：`google_global`
- CN 私有入口使用动态 HMAC 头；运行时需提供 `DQUERY_HMAC_SECRET`，可选 `DQUERY_KEY_ID`
- 支持 stale-if-error
- 支持 `all_answers_cn` 动态学习

## 注意

当前压缩包内仍然没有 `go.sum`。这是因为当前离线容器里无法访问 Go 模块源，没法为你在本地完整拉依赖并生成校验文件。你上传到 VPS 后执行一次 `go mod tidy` 即可补齐。
## account-system 接入：dquery personal DNS console

`mydquery` 的公共 DNS 查询页继续保持匿名可用，不强制登录。  
统一账户接入仅用于后续的 `dquery personal DNS console`，例如个人规则、查询历史、私有配置和审计能力。

### account-system 后台创建 API 接入

在 `https://account.js.gripe/dashboard` 的 API 接入页面中新建：

- 名称：`dquery personal DNS console`
- 回调地址：`https://dns.js.gripe/auth/account/callback`
- 权限范围：
  - `accounts:read`
  - `identities:resolve`

创建完成后请立即保存：

- `client_id`：形如 `cli_xxx`
- `apikey / clientSecret`：只显示一次

不要把应用名称当成 `client_id` 使用。

### 运行配置

生产配置文件路径：

```text
/etc/dquery/config.json