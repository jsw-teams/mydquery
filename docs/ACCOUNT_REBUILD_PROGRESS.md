# dquery account rebuild progress

更新时间：2026-05-10

## 已完成

- 公共查询页保持独立，并在右上角提供控制台入口。
- 登录页独立为 `/login/`，使用账户中心第三方跳转授权登录。
- 2026-05-09：账户中心登录模型更新后，dquery 登录页改为第三方跳转授权登录，不再收集邮箱和密码。
- `/login/` 会跳转到 `https://account.js.gripe/login?client_id=...&redirect_uri=...&scope=...&state=...`，回调拿到 `account_session` 后写入浏览器 sessionStorage 并返回 `/console/`。
- 部署前需要在账户中心创建 dquery API 接入，登记 `https://dns.js.gripe/login/` 为 redirect URI，并把 `LoginPanel.astro` 里的 `clientId` 更新为真实 API 接入 ID。
- 2026-05-09：已发布新前端到生产 release `/var/www/dqueryd/releases/20260509214840`，`/var/www/dqueryd/current` 已切换到该版本。
- 2026-05-09：已同步 OpenResty 生产配置，补齐 `/_astro/` 静态资源 location，并添加 `/login` -> `/login/`、`/console` -> `/console/` 跳转。
- 2026-05-09：处理 account-system 第三方授权 404。根因是 account-system systemd 进程仍为 2026-05-07 启动的旧代码，未加载 `/auth/authorize` 路由；重启服务后路由生效。
- 2026-05-09：账户中心数据库补齐 `dquery` API 接入，redirect URI 为 `https://dns.js.gripe/login/`，scopes 为 `accounts:read`、`identities:resolve`，解决授权阶段 `client_not_found`。
- 2026-05-09：处理登录成功后返回登录页问题。根因是生产 dqueryd 二进制仍为旧版本，缺少 `/api/v1/dquery/session` 账户控制台 API；已重新构建并重启 dqueryd。
- 2026-05-09：前端登录页移除默认调试状态文案，按钮改为“使用技诉账户登录”，公共查询页右上角“控制台 / English”链接改为同高居中对齐。
- 2026-05-09：已发布前端修复到生产 release `/var/www/dqueryd/releases/20260509223052`，并备份旧 dqueryd 二进制到 `/opt/dquery/bin/dqueryd.bak.20260509222727`。
- 2026-05-09：控制台 CORS 修复，gateway dquery 预检允许 `Authorization`、`X-ECS`、`PATCH`、`DELETE`，并透传 `Authorization` 到 dqueryd。
- 2026-05-09：登录页改为小窗打开账户中心授权；小窗回调通过 `postMessage`、`BroadcastChannel` 和同源地址轮询 fallback 回传 token。返回公共查询链接与账户登录按钮分为上下两块。
- 2026-05-09：管理后台重构为核心功能：退出账户、DoH 端点显示、名单拦截规则集管理、拦截行为设置、查询日志查询。旧 Profile/Token/上游/自定义规则入口已从新控制台移除。
- 2026-05-09：规则集支持 UI 选择著名预设（HaGeZi、AdGuard、OISD）或自定义 URL；规则集默认拦截行为为“不解析”。拦截行为可切换为“劫持到自定义拦截页”并编辑 URL。
- 2026-05-09：查询日志只保留最近 1 天，写入和查询时都会清理 24 小时前记录。
- 2026-05-09：已发布后台重构到生产 release `/var/www/dqueryd/releases/20260509233540`，并备份旧 dqueryd 二进制到 `/opt/dquery/bin/dqueryd.bak.20260509233540`。
- 2026-05-09：修复后台模块显示和文本溢出问题，非当前模块强制隐藏；规则集卡片和列表长 URL 支持换行；规则集状态明确显示“已启用 / 待同步”等状态。
- 2026-05-09：查询日志新增用户手动清空能力，`DELETE /api/v1/dquery/logs` 每用户 30 秒限速，避免频繁写操作影响平台稳定。
- 2026-05-09：已发布模块隔离、日志清空和文字溢出修复到生产 release `/var/www/dqueryd/releases/20260509235655`，并备份旧 dqueryd 二进制到 `/opt/dquery/bin/dqueryd.bak.20260509235654`。
- 2026-05-10：恢复 account-system 中固定 `dquery` API 接入，redirect URI 为 `https://dns.js.gripe/login/`，scopes 为 `accounts:read`、`identities:resolve`。
- 2026-05-10：dquery 第三方登录 URL 新增 `prompt=consent`；account-system 在已有本地登录态时不再静默授权或静默进入后台，而是显示“继续使用该账户 / 切换账户 / 让此浏览器忘记该账户”确认面板。
- 2026-05-10：控制台规则集预设卡片和规则集表单再次修复长文本布局，卡片内容允许换行并自动撑开，避免 HaGeZi / AdGuard URL 被裁切。
- 2026-05-10：已发布前端修复到生产 release `/var/www/dqueryd/releases/20260510001524`，并重启 account-system 服务使登录确认逻辑生效。
- 2026-05-10：规则集预设改为单列简要列表，只显示规则名称和精简来源；account-system 用户/API 删除按钮移除 `ghost` 样式，避免删除文字在按钮状态切换时不可见。
- 2026-05-10：已发布规则集文字和 account-system 删除按钮修复到生产 release `/var/www/dqueryd/releases/20260510002821`，并重启 account-system 服务。
- 2026-05-10：第三方登录确认页“让此浏览器忘记该账户”按钮移除 `ghost` 样式；dquery 登录小窗只有在用户关闭且未完成授权时才显示“未完成授权”，成功回调不再短暂显示失败状态。
- 2026-05-10：dquery 登录页“返回公共查询”按钮改为内容宽度并靠左，不再与“使用技诉账户登录”等宽。
- 2026-05-10：account-system README 更新第三方跳转授权细节，补充 `prompt=consent`、`prompt=login`、账户确认页、小窗关闭后再提示未授权等接入规范。
- 2026-05-10：已发布第三方登录体验修复到生产 release `/var/www/dqueryd/releases/20260510004605`，并重启 account-system 服务。
- 2026-05-10：规则集改为平台维护著名规则集来源（HaGeZi、AdGuard、OISD），启动时或超过 1 周才自动同步，避免每次用户操作触发长同步。
- 2026-05-10：用户侧规则集仅允许对著名规则集逐个启用/禁用；不再支持提交自定义规则集 URL。
- 2026-05-10：新增“域名规则”板块，用户通过 UI 对单个域名选择“跳过规则集”（白名单）或“拦截”。
- 2026-05-10：个人 DoH 请求会先应用用户域名覆盖规则；白名单跳过规则集，强制拦截返回 NXDOMAIN；随后只检查用户已启用的著名规则集。
- 2026-05-10：修复 dquery 登录小窗关闭判定 race，继续使用技诉账户成功授权后不再短暂显示“未完成授权，请重新登录”。
- 2026-05-10：已发布规则集启用偏好和域名规则到生产 release `/var/www/dqueryd/releases/20260510094130`，并备份旧二进制到 `/opt/dquery/bin/dqueryd.bak.20260510094130`。
- 控制台页独立为 `/console/`，未登录状态自动返回 `/login`。
- 控制台新增侧边栏：总览、规则集、拦截行为、查询日志、账户。
- 控制台概览显示个人 DoH 入口：`https://gateway.js.gripe/api/v1/dquery/{account_user_id}`。
- 后端接受 `/api/v1/dquery/usr_...` 形式的个人 DoH 入口。
- 规则集订阅由用户自选启用；当前仅支持平台内置著名规则集，用户不能提交自定义 URL。
- 已启用规则集支持禁用，后端提供 `PATCH /api/v1/dquery/rulesets/{rulesetId}` 设置 `enabled`。
- 域名覆盖规则提供 `GET/POST/DELETE /api/v1/dquery/domain-rules`，支持白名单跳过规则集和强制拦截。
- 前端使用浏览器语言做中英文文案适配，并保留无障碍用的 skip link、role/status、aria label。
- 像素风素材来自 `/opt/jsgripe-pic`，已裁剪到 `frontend/public/media/`。

## 验证

- `npm run build`
- `node /opt/dquery/frontend/tests/smoke.mjs`
- `GOCACHE=/tmp/dquery-go-cache go test ./internal/server`
- 本机直连生产 Host/SNI 验证：`/` 已包含 `/console/` 入口，`/login/` 返回 200，`/login` 和 `/console` 返回 301，当前 `_astro` CSS 返回 200。
- account-system 验证：`npm test` 通过 9 项；`npm run ui:smoke` 通过；使用测试账号经 gateway 本机直连调用 `POST /api/v1/myaccount/auth/authorize` 返回 200，并生成回跳 `https://dns.js.gripe/login/` 的 callback URL。
- dquery 登录验证：使用测试账号完成账户中心授权后，`GET https://gateway.js.gripe/api/v1/dquery/session` 返回 200 和账户用户信息，控制台不再因 session API 404 回到登录页。
- 前端验证：登录页静态 HTML 不再包含“准备就绪”/`Ready.`，包含“使用技诉账户登录”；Playwright smoke 桌面和移动端通过。
- 后台重构验证：smoke 覆盖规则集预设选择/启用/取消、拦截页 URL 保存、日志查询，并检查桌面和移动端横向溢出及文字溢出。
- 生产 API 验证：`OPTIONS /api/v1/dquery/settings` 允许 `PATCH`；真实 token 调用 `/session`、`/settings`、`PATCH /settings`、`/rulesets`、`/logs` 均返回 200。
- 日志清空验证：`OPTIONS /api/v1/dquery/logs` 允许 `DELETE`；真实 token 第一次 `DELETE /logs` 返回 200，连续第二次返回 429 `rate_limited`。
- 模块与样式验证：smoke 确认控制台一次只显示一个模块，规则集启用状态明确，桌面和移动端无横向溢出及明显文字溢出。
- 2026-05-10 验证：`npm test`、`npm run ui:smoke`、`npm run build`、`node /opt/dquery/frontend/tests/smoke.mjs` 均通过；预览图片保留在 `/tmp/dquery-desktop.png`、`/tmp/dquery-mobile.png`、`/tmp/account-ui-smoke-dashboard.png`，其余本次 tmp 测试目录已清理。
- 2026-05-10 规则集文字修复验证：`npm run build`、`node /opt/dquery/frontend/tests/smoke.mjs`、`npm run ui:smoke` 均通过；本次 tmp 测试目录已清理，预览图片保留。
- 2026-05-10 第三方登录体验验证：`node --check` 校验 dquery/account-system 前端脚本，`npm run build`、`node /opt/dquery/frontend/tests/smoke.mjs`、`npm run ui:smoke`、`npm test` 均通过；本次 tmp 测试目录已清理，预览图片保留。
- 2026-05-10 规则集启用偏好验证：`go test ./...`、`npm run build`、`node /opt/dquery/frontend/tests/smoke.mjs` 均通过；生产 readyz 正常，四个著名规则集同步完成，测试账户可通过 API 启用/禁用单独规则集并读取空域名规则列表。
- Playwright smoke 使用 HTTP 静态服务验证 CSS/JS 真实加载，不再使用 `file://`。
- smoke 覆盖公共查询页、登录页、未登录控制台跳转和登录态新控制台核心交互。
- 测试账号 `test@js.gripe` 已通过本机 account-system 旧登录接口验证，返回 active `member` 用户 `usr_cc37abf5-a437-4f22-87f9-90763fa8f29a`。新流程需在 dquery API 接入登记完成后通过浏览器授权回跳验证。
- 公网账户中心授权回跳需在 dquery API 接入登记完成后，用浏览器完成端到端验证；直接 curl 账户中心/网关会遇到 Cloudflare challenge，不作为本轮通过条件。

## 待继续

- 拦截页模式下为 A/AAAA 查询返回自定义拦截页地址对应记录，当前规则集和域名强制拦截先返回 NXDOMAIN。
- 继续补充真实浏览器端到端登录截图验证。
