import { chromium } from "/opt/account-system/node_modules/playwright/index.mjs";
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";

const distDir = "/opt/dquery/frontend/dist";
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8"
};

const server = createServer((request, response) => {
  const url = new URL(request.url || "/", "http://127.0.0.1");
  const pathname = decodeURIComponent(url.pathname);
  const normalized = normalize(pathname).replace(/^(\.\.[/\\])+/, "");
  let filePath = join(distDir, normalized);
  if (pathname.endsWith("/")) {
    filePath = join(filePath, "index.html");
  }
  if (existsSync(filePath) && statSync(filePath).isDirectory()) {
    filePath = join(filePath, "index.html");
  }
  if (!existsSync(filePath)) {
    response.writeHead(404);
    response.end("not found");
    return;
  }
  response.writeHead(200, { "Content-Type": mimeTypes[extname(filePath)] || "application/octet-stream" });
  createReadStream(filePath).pipe(response);
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();
const origin = `http://127.0.0.1:${port}`;

const viewports = [
  { name: "desktop", width: 1440, height: 1100 },
  { name: "mobile", width: 390, height: 900 }
];

const browser = await chromium.launch({ headless: true });
const failures = [];

try {
  for (const viewport of viewports) {
    const page = await browser.newPage({ viewport });
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${origin}/`, { waitUntil: "networkidle" });
    const indexMetrics = await page.evaluate(() => ({
      hasLookup: Boolean(document.querySelector(".lookup")?.getBoundingClientRect().height),
      hasConsole: Boolean(document.querySelector(".pixel-app")),
      widthOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      cssLoaded: getComputedStyle(document.querySelector(".lookup")).display === "block" && getComputedStyle(document.body).fontFamily.includes("Arial")
    }));
    if (!indexMetrics.hasLookup) failures.push(`${viewport.name}: public lookup missing`);
    if (indexMetrics.hasConsole) failures.push(`${viewport.name}: console leaked onto public lookup page`);
    if (indexMetrics.widthOverflow) failures.push(`${viewport.name}: public page horizontal overflow`);
    if (!indexMetrics.cssLoaded) failures.push(`${viewport.name}: public page css not loaded`);

    await page.goto(`${origin}/login/`, { waitUntil: "networkidle" });
    const loginMetrics = await page.evaluate(() => ({
      hasLogin: Boolean(document.querySelector(".login-card")?.getBoundingClientRect().height),
      cssLoaded: getComputedStyle(document.querySelector(".login-card")).display === "grid",
      hasReadyText: document.body.textContent.includes("准备就绪") || document.body.textContent.includes("Ready."),
      loginButtonWidth: document.querySelector("#login-button")?.getBoundingClientRect().width || 0,
      backLinkTop: document.querySelector(".login-secondary-action")?.getBoundingClientRect().top || 0,
      loginButtonBottom: document.querySelector("#login-button")?.getBoundingClientRect().bottom || 0,
      widthOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1
    }));
    if (!loginMetrics.hasLogin) failures.push(`${viewport.name}: login page missing`);
    if (!loginMetrics.cssLoaded) failures.push(`${viewport.name}: login css not loaded`);
    if (loginMetrics.hasReadyText) failures.push(`${viewport.name}: login page leaked ready debug text`);
    if (loginMetrics.backLinkTop <= loginMetrics.loginButtonBottom) failures.push(`${viewport.name}: public lookup link is on the same row as login button`);
    if (loginMetrics.widthOverflow) failures.push(`${viewport.name}: login horizontal overflow`);

    await page.goto(`${origin}/console/`, { waitUntil: "networkidle" });
    if (!page.url().includes("/login")) failures.push(`${viewport.name}: anonymous console did not redirect to login`);

    await page.route("https://gateway.js.gripe/api/v1/dquery/session", (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ok: true, user: { id: "usr_test", email: "test@js.gripe", display_name: "Test", role: "member", user_type: "member" }, capabilities: {}, initialized: true })
    }));
    await page.route("https://gateway.js.gripe/api/v1/dquery/settings", async (route) => {
      if (route.request().method() === "PATCH") {
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, settings: { owner_user_id: "usr_test", mode: "block_page", block_page_url: "https://dns.js.gripe/blocked", updated_at: "2026-05-09T00:00:00Z" } }) });
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, settings: { owner_user_id: "usr_test", mode: "nxdomain", block_page_url: "", updated_at: "" } }) });
    });
    await page.route("https://gateway.js.gripe/api/v1/dquery/rulesets", (route) => {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, rulesets: [{ id: "hagezi_multi_normal", name: "HaGeZi Multi NORMAL", source_url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt", status: "synced", enabled: false, domain_count: 123456, last_sync_at: "2026-05-09T00:00:00Z" }] }) });
    });
    await page.route("https://gateway.js.gripe/api/v1/dquery/rulesets/hagezi_multi_normal", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, ruleset: { id: "hagezi_multi_normal", name: "HaGeZi Multi NORMAL", source_url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi.txt", status: "synced", enabled: true, domain_count: 123456, last_sync_at: "2026-05-09T00:00:00Z" } }) }));
    await page.route("https://gateway.js.gripe/api/v1/dquery/domain-rules", (route) => {
      if (route.request().method() === "POST") {
        return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ ok: true, rule: { id: "act_new" } }) });
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, rules: [{ id: "act_test", owner_user_id: "usr_test", domain: "ads.example.com", match_type: "domain_suffix", action: "allow", enabled: true, created_at: "2026-05-09T00:00:00Z", updated_at: "2026-05-09T00:00:00Z" }] }) });
    });
    await page.route("https://gateway.js.gripe/api/v1/dquery/domain-rules/act_test", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) }));
    await page.route(/https:\/\/gateway\.js\.gripe\/api\/v1\/dquery\/logs.*/, (route) => {
      if (route.request().method() === "DELETE") {
        return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) });
      }
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true, logs: [{ id: "log_test", owner_user_id: "usr_test", qname: "example.com", qtype: "A", action: "resolve", created_at: "2026-05-09T00:00:00Z" }] }) });
    });
    await page.addInitScript(() => sessionStorage.setItem("dquery.accountToken", "test-token"));
    await page.goto(`${origin}/console/`, { waitUntil: "networkidle" });

    await page.getByRole("button", { name: /规则集|Rule sets/ }).click();
    await page.getByText(/HaGeZi Multi NORMAL/).waitFor({ state: "visible" });
    await page.getByRole("button", { name: /启用|Enable/ }).click();
    await page.getByRole("button", { name: /域名规则|Domain rules/ }).click();
    await page.fill("#domain-rule-domain", "ads.example.com");
    await page.locator('.segmented[data-control="domain_action"]').getByRole("button", { name: /拦截|Block/ }).click();
    await page.getByRole("button", { name: /保存域名规则|Save domain rule/ }).click();
    await page.getByRole("button", { name: /删除|Delete/ }).first().click();
    await page.getByRole("button", { name: /拦截行为|Blocking/ }).click();
    await page.getByRole("button", { name: /劫持到拦截页|Hijack to block page/ }).click();
    await page.fill("#block-page-url", "https://dns.js.gripe/blocked");
    await page.getByRole("button", { name: /保存拦截行为|Save behavior/ }).click();
    await page.getByRole("button", { name: /查询日志|Logs/ }).first().click();
    await page.fill("#log-query", "example.com");
    await page.getByRole("button", { name: /查询日志|Search logs/ }).last().click();
    await page.getByRole("button", { name: /清空日志|Clear logs/ }).click();

    const metrics = await page.evaluate(() => ({
      title: document.querySelector("#console-title")?.textContent?.trim(),
      status: document.querySelector("#session-status")?.textContent?.trim(),
      widthOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      consoleVisible: Boolean(document.querySelector(".pixel-app")?.getBoundingClientRect().height),
      sidebarVisible: Boolean(document.querySelector(".pixel-sidebar")?.getBoundingClientRect().height),
      endpointVisible: Boolean(document.querySelector("#personal-endpoint")),
      lookupVisible: Boolean(document.querySelector(".lookup")),
      cssLoaded: getComputedStyle(document.querySelector(".pixel-app")).display === "grid",
      visiblePanels: Array.from(document.querySelectorAll(".console-view")).filter((node) => getComputedStyle(node).display !== "none").length,
      rulesetStatus: document.querySelector("#ruleset-list .data-item em")?.textContent?.trim() || "",
      domainRuleStatus: document.querySelector("#domain-rule-list .data-item em")?.textContent?.trim() || "",
      textOverflowCount: Array.from(document.querySelectorAll("button, a, span, strong, code, input, .data-item, .endpoint-box, .preset-card"))
        .filter((node) => node.scrollWidth > node.clientWidth + 2).length
    }));

    if (!/Personal DNS Console|个人 DNS 控制台/.test(metrics.title || "")) failures.push(`${viewport.name}: missing console title`);
    if (!metrics.status) failures.push(`${viewport.name}: missing session status`);
    if (metrics.widthOverflow) failures.push(`${viewport.name}: horizontal overflow`);
    if (metrics.visiblePanels !== 1) failures.push(`${viewport.name}: expected one active console module, got ${metrics.visiblePanels}`);
    if (!/已启用|Enabled/.test(metrics.rulesetStatus) || !/已同步|Synced/.test(metrics.rulesetStatus)) failures.push(`${viewport.name}: known ruleset enabled/sync status is not explicit`);
    if (!/跳过规则集|Skip rule sets/.test(metrics.domainRuleStatus)) failures.push(`${viewport.name}: domain rule status is not explicit`);
    if (metrics.textOverflowCount > 0) failures.push(`${viewport.name}: ${metrics.textOverflowCount} text nodes overflow their UI boxes`);
    if (!metrics.consoleVisible || !metrics.sidebarVisible || !metrics.endpointVisible || metrics.lookupVisible) failures.push(`${viewport.name}: console page sections incorrect`);
    if (!metrics.cssLoaded) failures.push(`${viewport.name}: console css not loaded`);
    if (pageErrors.length > 0) failures.push(`${viewport.name}: page errors: ${pageErrors.join("; ")}`);
    await page.screenshot({ path: `/tmp/dquery-${viewport.name}.png`, fullPage: true });
    await page.close();
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}

if (failures.length > 0) {
  throw new Error(failures.join("\n"));
}

console.log("Playwright smoke passed for desktop and mobile.");
