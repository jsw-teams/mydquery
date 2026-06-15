const script = document.currentScript;
const apiBase = script?.dataset.endpoint || "/api/v1/dquery";
const lang = navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";

const copy = {
  en: {
    navOverview: "Overview", navRulesets: "Rule sets", navDomainRules: "Domain rules", navBlocking: "Blocking", navLogs: "Logs", navAccount: "Account",
    publicLookup: "Public lookup", kicker: "Account DNS", title: "Personal DNS Console", logout: "Sign out",
    endpointTitle: "DoH endpoint", personalEndpoint: "Personal DoH endpoint", rulesetCount: "Rule sets", blockMode: "Blocking mode", logWindow: "Log retention",
    rulesetsTitle: "Blocklist rule sets", rulesetNote: "Known rule sets are managed by the platform. Choose which lists are active for your DNS endpoint.", enableRuleset: "Enable", disableRuleset: "Disable",
    domainRulesTitle: "Domain override rules", domainRulesNote: "Choose whether a domain skips the rule sets or is blocked.", domainName: "Domain", domainAction: "Action", domainScope: "Scope", actionAllow: "Skip rule sets", actionBlock: "Block", scopeSuffix: "Domain + subdomains", scopeExact: "This domain only", saveDomainRule: "Save domain rule", deleteRule: "Delete",
    blockingTitle: "Blocking behavior", modeNxdomain: "Do not resolve", modeBlockPage: "Redirect to target", blockPageUrl: "Block target CNAME / IP", saveBlocking: "Save behavior",
    logsTitle: "Query logs", logsNote: "Only the most recent 24 hours are retained.", logSearch: "Domain filter", searchLogs: "Search logs", clearLogs: "Clear logs", topQueriedDomains: "Most queried domains", topBlockedDomains: "Most blocked domains", accountTitle: "Account",
    enabled: "Enabled", disabled: "Disabled", pending: "Pending", synced: "Synced", error: "Sync error", connected: "Connected", saved: "Saved", logsCleared: "Logs cleared", signedOut: "Signed out", loadFailed: "Connection failed. Please check network or CORS settings.", emptySets: "No known rule sets are available.", emptyDomainRules: "No domain override rules yet.", emptyLogs: "No query logs in the last 24 hours.", emptyChart: "No data yet"
  },
  zh: {
    navOverview: "总览", navRulesets: "规则集", navDomainRules: "域名规则", navBlocking: "拦截行为", navLogs: "查询日志", navAccount: "账户",
    publicLookup: "公共查询", kicker: "账户 DNS", title: "个人 DNS 控制台", logout: "退出账户",
    endpointTitle: "DoH 端点", personalEndpoint: "个人 DoH 入口", rulesetCount: "规则集", blockMode: "拦截模式", logWindow: "日志保留",
    rulesetsTitle: "名单拦截规则集", rulesetNote: "著名规则集由平台维护。你可以选择哪些规则集对个人 DNS 生效。", enableRuleset: "启用", disableRuleset: "禁用",
    domainRulesTitle: "域名覆盖规则", domainRulesNote: "为域名选择跳过规则集规则或直接拦截。", domainName: "域名", domainAction: "行为", domainScope: "范围", actionAllow: "跳过规则集", actionBlock: "拦截", scopeSuffix: "域名及子域名", scopeExact: "仅此域名", saveDomainRule: "保存域名规则", deleteRule: "删除",
    blockingTitle: "拦截行为", modeNxdomain: "不解析", modeBlockPage: "定向到目标", blockPageUrl: "拦截目标 CNAME / IP", saveBlocking: "保存拦截行为",
    logsTitle: "查询日志", logsNote: "仅保留最近 1 天。", logSearch: "域名过滤", searchLogs: "查询日志", clearLogs: "清空日志", topQueriedDomains: "查询最多域名", topBlockedDomains: "拦截最多域名", accountTitle: "账户",
    enabled: "已启用", disabled: "已禁用", pending: "待同步", synced: "已同步", error: "同步异常", connected: "已连接", saved: "已保存", logsCleared: "日志已清空", signedOut: "已退出", loadFailed: "连接失败，请检查网络或 CORS 设置。", emptySets: "暂无可用著名规则集。", emptyDomainRules: "还没有域名覆盖规则。", emptyLogs: "最近 1 天没有查询日志。", emptyChart: "暂无数据"
  }
};

const state = { user: null, settings: { mode: "nxdomain", block_page_url: "" }, rulesets: [], domainRules: [], domainAction: "allow", domainMatchType: "domain_suffix", logs: [], logStats: { queried: [], blocked: [] } };
const els = {
  status: document.querySelector("#session-status"), endpoint: document.querySelector("#personal-endpoint"), metricRulesets: document.querySelector("#metric-rulesets"), metricBlockMode: document.querySelector("#metric-block-mode"),
  rulesetList: document.querySelector("#ruleset-list"), domainRuleForm: document.querySelector("#domain-rule-form"), domainRuleDomain: document.querySelector("#domain-rule-domain"), domainRuleList: document.querySelector("#domain-rule-list"),
  blockURL: document.querySelector("#block-page-url"), saveBlocking: document.querySelector("#save-blocking"), logForm: document.querySelector("#log-form"), logQuery: document.querySelector("#log-query"), clearLogs: document.querySelector("#clear-logs"), logList: document.querySelector("#log-list"), topQueryDomains: document.querySelector("#top-query-domains"), topBlockedDomains: document.querySelector("#top-blocked-domains"), accountEmail: document.querySelector("#account-email"), toast: document.querySelector("#console-toast")
};

document.querySelectorAll("[data-i18n]").forEach((node) => { const value = copy[lang][node.dataset.i18n]; if (value) node.textContent = value; });

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const response = await fetch(`${apiBase}${path}`, { ...options, credentials: "include", headers, cache: "no-store" });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) { const error = new Error(payload.error || `HTTP ${response.status}`); error.status = response.status; throw error; }
  return payload;
}
function setStatus(message, tone = "") { els.status.textContent = message; els.status.dataset.tone = tone; }
function showToast(message, tone = "ok") {
  if (!els.toast) return;
  window.clearTimeout(showToast.timer);
  els.toast.textContent = message;
  els.toast.dataset.tone = tone;
  els.toast.classList.add("show");
  showToast.timer = window.setTimeout(() => els.toast.classList.remove("show"), 2600);
}
function withTrailingSlash(path) {
  if (!path.startsWith("/")) return "/login/";
  if (path.includes("?") || path.includes("#")) {
    const url = new URL(path, window.location.origin);
    if (!url.pathname.endsWith("/")) url.pathname += "/";
    return `${url.pathname}${url.search}${url.hash}`;
  }
  return path.endsWith("/") ? path : `${path}/`;
}
function redirectToLogin() { window.location.replace(withTrailingSlash("/login")); }
function redirectToSetup() { window.location.replace(withTrailingSlash("/setup")); }
async function signOut() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    // Local cleanup still wins if the network is already gone.
  }
  setStatus(copy[lang].signedOut, "ok");
  window.location.replace(withTrailingSlash("/login"));
}
function empty(text) { const node = document.createElement("div"); node.className = "empty-state"; node.textContent = text; return node; }
function item(label, meta, chip) { const row = document.createElement("div"); row.className = "data-item"; row.innerHTML = "<div><strong></strong><span></span></div><em></em>"; row.querySelector("strong").textContent = label; row.querySelector("span").textContent = meta; row.querySelector("em").textContent = chip; return row; }
function modeLabel(mode) { return mode === "block_page" ? copy[lang].modeBlockPage : copy[lang].modeNxdomain; }

function showView(view) {
  const panels = Array.from(document.querySelectorAll(".console-view"));
  const target = panels.some((panel) => panel.dataset.panel === view) ? view : "overview";
  document.querySelectorAll(".side-nav button").forEach((button) => {
    const active = button.dataset.view === target;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  panels.forEach((panel) => {
    const active = panel.dataset.panel === target;
    panel.classList.toggle("active", active);
    panel.hidden = !active;
    panel.style.display = active ? "grid" : "none";
  });
  if (window.location.hash !== `#${target}`) {
    window.history.replaceState({}, "", `#${target}`);
  }
}
function setBlockMode(mode) {
  state.settings.mode = mode;
  document.querySelectorAll('.segmented[data-control="block_mode"] button').forEach((button) => button.classList.toggle("active", button.dataset.value === mode));
  els.metricBlockMode.textContent = mode === "block_page" ? "BLOCK PAGE" : "NXDOMAIN";
}
function setDomainMatchType(matchType) {
  state.domainMatchType = matchType;
  document.querySelectorAll('.segmented[data-control="domain_match_type"] button').forEach((button) => button.classList.toggle("active", button.dataset.value === matchType));
}
function matchTypeLabel(matchType) { return matchType === "exact" ? copy[lang].scopeExact : copy[lang].scopeSuffix; }
function compactSource(value) {
  try {
    const url = new URL(value);
    const parts = url.pathname.split("/").filter(Boolean);
    const hint = parts.slice(0, 2).join("/");
    return hint ? `${url.hostname} / ${hint}` : url.hostname;
  } catch {
    return String(value || "").replace(/^https?:\/\//, "").slice(0, 56);
  }
}
function renderRulesets() {
  els.metricRulesets.textContent = String(state.rulesets.length);
  els.rulesetList.replaceChildren();
  if (state.rulesets.length === 0) { els.rulesetList.append(empty(copy[lang].emptySets)); return; }
  for (const set of state.rulesets) {
    const statusLabel = `${set.enabled ? copy[lang].enabled : copy[lang].disabled} / ${copy[lang][set.status] || set.status || copy[lang].pending} / ${set.domain_count || 0}`;
    const row = item(set.name, compactSource(set.source_url), statusLabel);
    row.dataset.enabled = String(set.enabled === true);
    const button = document.createElement("button");
    button.type = "button";
    button.className = `pixel-button small ${set.enabled ? "danger" : ""}`;
    button.textContent = set.enabled ? copy[lang].disableRuleset : copy[lang].enableRuleset;
    button.addEventListener("click", () => updateRuleset(set.id, !set.enabled));
    row.append(button);
    els.rulesetList.append(row);
  }
}
function renderDomainRules() {
  els.domainRuleList.replaceChildren();
  if (state.domainRules.length === 0) { els.domainRuleList.append(empty(copy[lang].emptyDomainRules)); return; }
  for (const rule of state.domainRules) {
    const row = item(rule.domain, matchTypeLabel(rule.match_type), rule.action === "block" ? copy[lang].actionBlock : copy[lang].actionAllow);
    row.dataset.enabled = String(rule.enabled !== false);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "pixel-button danger small";
    button.textContent = copy[lang].deleteRule;
    button.addEventListener("click", () => deleteDomainRule(rule.id));
    row.append(button);
    els.domainRuleList.append(row);
  }
}
function renderLogs() {
  renderLogCharts();
  els.logList.replaceChildren();
  if (state.logs.length === 0) { els.logList.append(empty(copy[lang].emptyLogs)); return; }
  for (const entry of state.logs) els.logList.append(item(`${entry.qname} / ${entry.qtype}`, entry.created_at, entry.action));
}
function renderLogCharts() {
  renderChart(els.topQueryDomains, state.logStats.queried || []);
  renderChart(els.topBlockedDomains, state.logStats.blocked || []);
}
function renderChart(target, rows) {
  if (!target) return;
  target.replaceChildren();
  if (!rows.length) { target.append(empty(copy[lang].emptyChart)); return; }
  const max = Math.max(...rows.map((row) => row.count || 0), 1);
  for (const row of rows) {
    const bar = document.createElement("div");
    bar.className = "chart-bar";
    const width = Math.max(8, Math.round((Number(row.count || 0) / max) * 100));
    bar.innerHTML = "<div><strong></strong><span></span></div><em></em>";
    bar.querySelector("strong").textContent = row.domain;
    bar.querySelector("span").style.width = `${width}%`;
    bar.querySelector("em").textContent = String(row.count || 0);
    target.append(bar);
  }
}
async function loadAll() {
  try {
    const setup = await api("/setup/status");
    if (!setup.initialized) { redirectToSetup(); return; }
    const [session, settings, rulesets, domainRules, logs, logStats] = await Promise.all([api("/session"), api("/settings"), api("/rulesets"), api("/domain-rules"), api("/logs"), api("/logs/stats")]);
    state.user = session.user;
    state.settings = settings.settings || state.settings;
    state.rulesets = rulesets.rulesets || [];
    state.domainRules = domainRules.rules || [];
    state.logs = logs.logs || [];
    state.logStats = logStats.stats || state.logStats;
    const resolverUUID = session.default_resolver_uuid || session.profiles?.[0]?.resolver_uuid || "";
    els.endpoint.textContent = resolverUUID ? `https://dquery.js.gripe/dns-query/${resolverUUID}` : "-";
    els.accountEmail.textContent = state.user.email || state.user.id;
    els.blockURL.value = state.settings.block_page_url || "";
    setBlockMode(state.settings.mode || "nxdomain");
    renderRulesets();
    renderDomainRules();
    renderLogs();
    setStatus(`${copy[lang].connected}: ${state.user.email || state.user.id}`, "ok");
  } catch (error) {
    if (error.status === 401 || error.status === 403) { redirectToLogin(); return; }
    setStatus(copy[lang].loadFailed, "bad");
  }
}
async function saveBlocking() {
  const payload = { mode: state.settings.mode || "nxdomain", block_page_url: els.blockURL.value };
  const result = await api("/settings", { method: "PATCH", body: JSON.stringify(payload) });
  state.settings = result.settings;
  setBlockMode(state.settings.mode);
  setStatus(copy[lang].saved, "ok");
  showToast(copy[lang].saved);
}
function setDomainAction(action) {
  state.domainAction = action;
  document.querySelectorAll('.segmented[data-control="domain_action"] button').forEach((button) => button.classList.toggle("active", button.dataset.value === action));
}
async function saveDomainRule(event) {
  event.preventDefault();
  const payload = { domain: els.domainRuleDomain.value, match_type: state.domainMatchType, action: state.domainAction };
  await api("/domain-rules", { method: "POST", body: JSON.stringify(payload) });
  els.domainRuleDomain.value = "";
  state.domainRules = (await api("/domain-rules")).rules || [];
  renderDomainRules();
  setStatus(copy[lang].saved, "ok");
  showToast(copy[lang].saved);
}
async function updateRuleset(id, enabled) {
  const result = await api(`/rulesets/${id}`, { method: "PATCH", body: JSON.stringify({ enabled }) });
  state.rulesets = state.rulesets.map((set) => set.id === id ? result.ruleset : set);
  renderRulesets();
  setStatus(copy[lang].saved, "ok");
  showToast(copy[lang].saved);
}
async function deleteDomainRule(id) {
  await api(`/domain-rules/${id}`, { method: "DELETE" });
  state.domainRules = (await api("/domain-rules")).rules || [];
  renderDomainRules();
  showToast(copy[lang].saved);
}
async function searchLogs(event) {
  event.preventDefault();
  const q = encodeURIComponent(els.logQuery.value.trim());
  const [logs, logStats] = await Promise.all([api(`/logs${q ? `?q=${q}` : ""}`), api("/logs/stats")]);
  state.logs = logs.logs || [];
  state.logStats = logStats.stats || state.logStats;
  renderLogs();
}
async function clearLogs() {
  await api("/logs", { method: "DELETE" });
  state.logs = [];
  state.logStats = { queried: [], blocked: [] };
  renderLogs();
  setStatus(copy[lang].logsCleared, "ok");
  showToast(copy[lang].logsCleared);
}

document.querySelectorAll(".side-nav button").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
document.querySelectorAll('.segmented[data-control="block_mode"] button').forEach((button) => button.addEventListener("click", () => setBlockMode(button.dataset.value)));
document.querySelectorAll('.segmented[data-control="domain_action"] button').forEach((button) => button.addEventListener("click", () => setDomainAction(button.dataset.value)));
document.querySelectorAll('.segmented[data-control="domain_match_type"] button').forEach((button) => button.addEventListener("click", () => setDomainMatchType(button.dataset.value)));
document.querySelectorAll("#logout-account, #logout-account-panel").forEach((button) => button.addEventListener("click", signOut));
els.saveBlocking?.addEventListener("click", saveBlocking);
els.domainRuleForm?.addEventListener("submit", saveDomainRule);
els.logForm?.addEventListener("submit", searchLogs);
els.clearLogs?.addEventListener("click", clearLogs);

showView(window.location.hash.replace("#", "") || "overview");
loadAll();
