# dquery account rebuild plan

目标：把 `dquery` 从公共 DoH 分流网关，重构为由统一账户中心识别用户、由 dquery 自己管理业务数据的个人 DNS 服务。

## 账户中心边界

账户中心按 `/opt/account-system/README.md` 的 2026-05 重写设计执行：

- 控制台：`https://account.js.gripe/dashboard`
- 登录页：`https://account.js.gripe/login`
- API 基础地址：`https://gateway.js.gripe/api/v1/myaccount`
- 业务 owner key：只使用账户中心返回的 `user.id`
- 用户类型：`system_admin`、`operator`、`auditor`、`member`
- 账户中心只管理统一用户、第三方身份绑定、API 接入凭据和账户侧审计
- 账户中心不管理 DNS profile、DNS 规则、上游选择、查询日志或 dquery 权限模型

这意味着 dquery 不能把邮箱、第三方平台 ID、旧本地管理员 ID 或旧测试数据当作业务主键。账户中心重建 SQLite 数据后，用户第一次进入 dquery 时按新的 `user.id` 创建默认 DNS profile。

## 当前已接入

dquery 当前已有账户中心客户端和探针接口：

- `internal/account/client.go`
- 配置项：`account.enabled`、`account.base_url`
- 探针接口：`GET /api/v1/dquery/account/me`

调用方式：

```bash
curl https://gateway.js.gripe/api/v1/dquery/account/me \
  -H "Authorization: Bearer <account-token>"
```

返回里的 `resource_owner_id` 等于账户中心 `user.id`，后续 profile、规则、token、审计日志都必须以它作为 owner。

需要补齐的账户侧约束：

- dquery 服务端应保存账户中心颁发的 API 接入 `clientId` / `clientSecret`，启动时或定期调用 `/apis/verify` 校验凭据。
- dquery 前端登录态继续使用账户中心 session token，但 token 只用于识别当前用户，不把账户后台管理能力暴露给 dquery。
- 调用账户中心失败时按 `code` 分支处理，尤其是 `account_disabled`：展示停用原因或支持邮箱，不自动创建新用户或降级为匿名用户。

## 重构边界

保留现有高质量解析核心：

- DoH wire 解析与响应链路
- CN / global 分流逻辑
- ECS 注入与选择
- LRU cache 与 stale-if-error
- ChinaMax 规则构建器与动态学习
- `healthz` / `readyz` 探活

新增 dquery 业务层：

- 用户 DNS profile
- 用户级规则 overlay
- 用户级 upstream policy
- profile token 管理
- 用户查询日志和命中统计
- dquery 侧业务审计
- account `user.id` 到 dquery owner 的首次初始化逻辑

不要新增的内容：

- 不在账户中心控制台编辑 DNS 规则
- 不把 dquery 的管理员、审计员或 DNS 配置写进账户中心
- 不用邮箱、GitHub ID、Google sub 等信息作为 dquery owner
- 不让浏览器直接持有账户中心 API 接入密钥

## 权限模型

账户中心用户类型只作为 dquery 入口权限的上游身份信号，dquery 内部仍需做自己的资源隔离。

建议映射：

| 账户类型 | dquery 默认能力 |
| --- | --- |
| `system_admin` | 可进入 dquery 全局运维视图，查看全局 profile、token、日志和运行状态 |
| `operator` | 可协助用户处理 profile、token、规则问题，但应记录业务审计 |
| `auditor` | 只读查看 dquery 审计和查询统计，不可修改 DNS 配置 |
| `member` | 只管理自己的 profile、规则、token 和查询日志 |

后端必须按 `owner_user_id` 校验资源归属。前端根据 dquery API 返回的 capability 裁剪导航，但所有权限仍由后端拦截。

## 数据模型建议

第一阶段使用 SQLite，路径建议独立于账户中心，例如 `/var/lib/dqueryd/dquery.sqlite3`。账户中心数据库重建不应删除 dquery 业务库，除非明确做全量重建。

```sql
CREATE TABLE dns_profiles (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  default_route TEXT NOT NULL DEFAULT 'auto',
  default_upstream_policy TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_dns_profiles_owner ON dns_profiles(owner_user_id);

CREATE TABLE dns_rules (
  id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  pattern TEXT NOT NULL,
  match_type TEXT NOT NULL DEFAULT 'domain_suffix',
  route TEXT NOT NULL DEFAULT 'auto',
  upstream_policy TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 100,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(profile_id) REFERENCES dns_profiles(id) ON DELETE CASCADE
);

CREATE INDEX idx_dns_rules_profile ON dns_rules(profile_id, enabled, priority);

CREATE TABLE dns_profile_tokens (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  last_used_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(profile_id) REFERENCES dns_profiles(id) ON DELETE CASCADE
);

CREATE INDEX idx_dns_profile_tokens_profile ON dns_profile_tokens(profile_id);

CREATE TABLE dns_query_logs (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  token_id TEXT,
  qname TEXT NOT NULL,
  qtype TEXT NOT NULL,
  route TEXT NOT NULL,
  upstream TEXT NOT NULL,
  rule_id TEXT,
  cache_status TEXT NOT NULL,
  rcode TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_dns_query_logs_owner_time ON dns_query_logs(owner_user_id, created_at);

CREATE TABLE dquery_audit_logs (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT NOT NULL,
  target_owner_user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
```

## API vNext

所有配置管理接口使用账户中心 session token：

```http
Authorization: Bearer <account-token>
Content-Type: application/json
```

建议新增：

- `GET /api/v1/dquery/session`：返回当前账户、dquery capability 和是否已初始化默认 profile
- `GET /api/v1/dquery/profiles`
- `POST /api/v1/dquery/profiles`
- `GET /api/v1/dquery/profiles/{id}`
- `PATCH /api/v1/dquery/profiles/{id}`
- `DELETE /api/v1/dquery/profiles/{id}`
- `GET /api/v1/dquery/profiles/{id}/rules`
- `POST /api/v1/dquery/profiles/{id}/rules`
- `PATCH /api/v1/dquery/profiles/{id}/rules/{ruleId}`
- `DELETE /api/v1/dquery/profiles/{id}/rules/{ruleId}`
- `GET /api/v1/dquery/profiles/{id}/tokens`
- `POST /api/v1/dquery/profiles/{id}/tokens`
- `PATCH /api/v1/dquery/profiles/{id}/tokens/{tokenId}`
- `DELETE /api/v1/dquery/profiles/{id}/tokens/{tokenId}`
- `GET /api/v1/dquery/profiles/{id}/queries`
- `GET /api/v1/dquery/admin/audit`

DoH 查询接口建议分成两类：

- 公共解析入口继续保留：`/api/v1/dquery`
- 个人 profile 入口新增：`/api/v1/dquery/p/{profileToken}` 或 `Authorization: Bearer <profile-token>`

profile token 只用于 DNS 查询，不用于管理接口。管理接口只接受账户中心 session token。

## 解析流程 vNext

公共入口维持当前流程：

1. 解析 DNS query。
2. 按 ChinaMax 和动态学习结果选择 CN / global route。
3. 注入或选择 ECS。
4. 查缓存、请求上游、写缓存。

个人入口新增 profile 维度：

1. 校验 profile token hash，得到 `owner_user_id`、`profile_id`、`token_id`。
2. 检查 profile 与 token 均为 active。
3. 加载 profile 默认 policy 和启用的规则 overlay。
4. 规则命中时按 priority 选择 route / upstream policy。
5. 未命中时回落 profile 默认 route；默认仍为当前 CN / global 自动分流。
6. cache key 必须包含 `profile_id`、命中规则或 policy 版本、route、upstream、ECS 和原始 DNS query。
7. 写入查询日志时脱敏客户端 IP，避免日志变成长期身份追踪库。

## 前端 vNext

`dns.js.gripe` 从公共展示站升级为 dquery 业务控制台。登录入口跳转到账户中心 `/login`，登录后通过 dquery API 获取 session 和 capability。

页面建议：

- Profile 列表与默认 profile
- Profile 详情、开关和默认路由
- 自定义域名规则
- 上游策略选择
- profile token 管理
- 查询日志和命中统计
- 管理员 / 审计员只读或运维视图

交互原则：

- Profile 开关使用 toggle。
- 默认 route、match type、upstream policy 使用 select 或 segmented control。
- 规则启停、route 选择使用按钮组或 chip。
- 域名 pattern、token 名称保留输入框，并在服务端校验。
- 停用账户、账户登录过期、`account_disabled` 等状态要给出明确提示，不静默回退为公共 DNS。

## 迁移顺序

1. 对齐账户中心接入：确认 `/me`、`/apis/verify`、`account_disabled` 错误处理和 dquery API 凭据配置。
2. 新增 dquery SQLite 业务库、迁移脚本和 repository 层。
3. 新增 `/api/v1/dquery/session`，首次登录自动创建默认 profile。
4. 新增 profile / rule / token 管理 API，并补资源归属校验。
5. 新增个人 DoH 入口，cache key 加入 profile 与 policy 维度。
6. 接入查询日志、命中统计和 dquery 审计日志。
7. 前端改造成业务控制台，公共说明页退为未登录状态或文档页。
8. 运维视图接入 `system_admin`、`operator`、`auditor` 的差异化能力。
9. 保留公共 `/api/v1/dquery` 作为无账户默认解析入口，等个人入口稳定后再决定是否限流或降级。

## 验收标准

- 账户中心重建 SQLite 后，dquery 不复用旧账户 ID、邮箱或本地管理员 ID。
- member 只能访问自己的 profile、rule、token、query log。
- operator / auditor / system_admin 的 dquery 能力由 dquery 后端返回并强制执行。
- profile token 不能调用管理 API。
- 停用账户访问 dquery 管理 API 时返回明确错误，不自动创建新 owner。
- 公共 DoH 行为保持兼容，个人 DoH 的缓存不会污染其他用户。
- 所有业务写操作进入 `dquery_audit_logs`。
