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
  - 中国域名：`https://hk-hkg.doh.sb/dns-query`
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

## 构建 ChinaMax 紧凑规则

```bash
/opt/dquery/bin/chinamax-build   -src /opt/dquery/vendor/ChinaMax_Classical.yaml   -include /opt/dquery/data/local-include.txt   -exclude /opt/dquery/data/local-exclude.txt   -out /var/lib/dqueryd/chinamax_classical.compact.json
```

## 说明

这份包默认维持：

- CN 主上游：`selfhosted_cn_1`
- CN 回退：`alidns_cn`
- Global 主上游：`cloudflare_gateway_global`
- Global 回退：`google_global`
- 支持 stale-if-error
- 支持 `all_answers_cn` 动态学习

## 注意

当前压缩包内仍然没有 `go.sum`。这是因为当前离线容器里无法访问 Go 模块源，没法为你在本地完整拉依赖并生成校验文件。你上传到 VPS 后执行一次 `go mod tidy` 即可补齐。
