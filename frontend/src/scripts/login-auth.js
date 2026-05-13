const script = document.currentScript;
const endpoint = script?.dataset.endpoint || "https://gateway.js.gripe/api/v1/dquery";
const lang = navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";

const text = {
  en: {
    kicker: "Account DNS",
    title: "Sign in to DNS Console",
    copy: "Use your JS.Gripe account. After authorization, you will return to this DNS console.",
    submit: "Sign in with JS.Gripe account",
    back: "Back to public lookup",
    failed: "Authorization failed. Please try again.",
    authorized: "Authorization completed. Returning to the console...",
    cancelled: "Authorization was not completed. Please sign in again.",
    popupBlocked: "Popup was blocked. Please allow popups and try again.",
    loadingClient: "Loading account application...",
    missingClient: "Missing dquery account client id."
  },
  zh: {
    kicker: "账户 DNS",
    title: "登录个人 DNS 控制台",
    copy: "使用技诉账户完成登录或注册，授权成功后会回到 DNS 控制台。",
    submit: "使用技诉账户登录",
    back: "返回公共查询",
    failed: "授权失败，请重试。",
    authorized: "授权已完成，正在返回控制台…",
    cancelled: "未完成授权，请重新登录。",
    popupBlocked: "登录小窗被拦截，请允许弹窗后重试。",
    loadingClient: "正在加载账户应用信息…",
    missingClient: "缺少 dquery 账户中心 client_id。"
  }
};

document.querySelectorAll("[data-i18n]").forEach((node) => {
  const value = text[lang][node.dataset.i18n];
  if (value) node.textContent = value;
});

const button = document.querySelector("#login-button");
const status = document.querySelector("#login-status");
const params = new URLSearchParams(window.location.search);
const authChannel = "BroadcastChannel" in window ? new BroadcastChannel("dquery-auth") : null;
const authResultKey = "dquery.authResult";
let authCompleted = false;
let authClient = null;

function setStatus(message, tone = "") {
  if (!status) return;
  status.textContent = message;
  status.dataset.tone = tone;
}

function randomState() {
  const values = new Uint8Array(16);
  crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

function completeCallback() {
  const returnedState = params.get("state") || "";
  const token = params.get("account_session") || "";
  if (!token || !returnedState) {
    setStatus(text[lang].failed, "bad");
    return;
  }
  authCompleted = true;
  persistAuthResult(token, returnedState);
  authChannel?.postMessage({ type: "dquery.accountAuthorized", token, state: returnedState });
  if (window.opener && window.opener !== window) {
    window.opener.postMessage({ type: "dquery.accountAuthorized", token, state: returnedState }, window.location.origin);
    setStatus(text[lang].authorized, "ok");
    window.setTimeout(() => window.close(), 120);
    return;
  }
  const expectedState = sessionStorage.getItem("dquery.authState") || "";
  if (expectedState && returnedState !== expectedState) {
    setStatus(text[lang].failed, "bad");
    return;
  }
  sessionStorage.setItem("dquery.accountToken", token);
  sessionStorage.removeItem("dquery.authState");
  const next = normalizeInternalPath(sessionStorage.getItem("dquery.authNext") || "/console/");
  sessionStorage.removeItem("dquery.authNext");
  window.location.replace(next);
}

function authorizeURL(state) {
  const redirectURI = authClient?.redirect_uri || `${window.location.origin}/login/`;
  const scopes = Array.isArray(authClient?.scopes) && authClient.scopes.length ? authClient.scopes.join(" ") : "accounts:read identities:resolve";
  const url = new URL(authClient?.login_url || "https://account.js.gripe/login");
  url.searchParams.set("client_id", authClient.client_id);
  url.searchParams.set("redirect_uri", redirectURI);
  url.searchParams.set("scope", scopes);
  url.searchParams.set("state", state);
  url.searchParams.set("prompt", "consent");
  return url;
}

function persistAuthResult(token, returnedState) {
  try {
    localStorage.setItem(authResultKey, JSON.stringify({ token, state: returnedState, createdAt: Date.now() }));
  } catch {
    // Best-effort fallback for popup close/message delivery races.
  }
}

function consumeAuthResult(expectedState) {
  try {
    const raw = localStorage.getItem(authResultKey);
    if (!raw) return null;
    const result = JSON.parse(raw);
    if (!result || Date.now() - Number(result.createdAt || 0) > 60_000) {
      localStorage.removeItem(authResultKey);
      return null;
    }
    if (result.state !== expectedState) return null;
    localStorage.removeItem(authResultKey);
    return result;
  } catch {
    localStorage.removeItem(authResultKey);
    return null;
  }
}

function finishAuthorizedSession(token, returnedState) {
  const expectedState = sessionStorage.getItem("dquery.authState") || "";
  if (!token || !returnedState || returnedState !== expectedState) {
    setStatus(text[lang].failed, "bad");
    return;
  }
  authCompleted = true;
  sessionStorage.setItem("dquery.accountToken", token);
  sessionStorage.removeItem("dquery.authState");
  const next = normalizeInternalPath(sessionStorage.getItem("dquery.authNext") || "/console/");
  sessionStorage.removeItem("dquery.authNext");
  window.location.replace(next);
}

function normalizeInternalPath(path) {
  const fallback = "/console/";
  if (!path || !path.startsWith("/")) return fallback;
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin) return fallback;
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return `${url.pathname}${url.search}${url.hash}`;
}

function startAuthorize() {
  if (!authClient?.client_id) {
    setStatus(text[lang].missingClient, "bad");
    return;
  }
  const next = normalizeInternalPath(params.get("next") || "/console/");
  const state = randomState();
  sessionStorage.setItem("dquery.authState", state);
  sessionStorage.setItem("dquery.authNext", next);
  const loginWindow = window.open(authorizeURL(state).toString(), "dqueryAccountLogin", "popup=yes,width=520,height=720,menubar=no,toolbar=no,location=yes,status=no,resizable=yes,scrollbars=yes");
  if (!loginWindow) {
    setStatus(text[lang].popupBlocked, "bad");
    return;
  }
  setStatus("", "");
  loginWindow.focus();
  const timer = window.setInterval(() => {
    if (loginWindow.closed) {
      window.clearInterval(timer);
      window.setTimeout(() => {
        const waitingState = sessionStorage.getItem("dquery.authState") || "";
        const storedResult = consumeAuthResult(state);
        if (storedResult) {
          finishAuthorizedSession(storedResult.token, storedResult.state);
          return;
        }
        if (!authCompleted && waitingState === state) {
          sessionStorage.removeItem("dquery.authState");
          sessionStorage.removeItem("dquery.authNext");
          setStatus(text[lang].cancelled, "bad");
        }
      }, 1500);
      return;
    }
    let href = "";
    try {
      href = loginWindow.location.href;
    } catch {
      return;
    }
    if (!href.startsWith(`${window.location.origin}/login`) && !href.startsWith(`${window.location.origin}/auth/account/callback`)) return;
    const callbackURL = new URL(href);
    const token = callbackURL.searchParams.get("account_session") || "";
    const returnedState = callbackURL.searchParams.get("state") || "";
    if (!token) return;
    window.clearInterval(timer);
    authCompleted = true;
    loginWindow.close();
    finishAuthorizedSession(token, returnedState);
  }, 400);
}

async function loadAuthClient() {
  if (!button) return;
  button.disabled = true;
  setStatus(text[lang].loadingClient, "");
  try {
    const response = await fetch(`${endpoint.replace(/\/$/, "")}/account/client`, {
      headers: { Accept: "application/json" },
      cache: "no-store"
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || !result?.client?.client_id) {
      throw new Error(result?.error || `http_${response.status}`);
    }
    authClient = result.client;
    setStatus("", "");
    button.disabled = false;
  } catch {
    authClient = null;
    setStatus(text[lang].missingClient, "bad");
  }
}

if (params.has("account_session")) {
  completeCallback();
} else {
  loadAuthClient();
}

window.addEventListener("message", (event) => {
  if (event.origin !== window.location.origin || event.data?.type !== "dquery.accountAuthorized") return;
  finishAuthorizedSession(event.data.token, event.data.state);
});

window.addEventListener("storage", (event) => {
  if (event.key !== authResultKey) return;
  const expectedState = sessionStorage.getItem("dquery.authState") || "";
  const storedResult = consumeAuthResult(expectedState);
  if (!storedResult) return;
  finishAuthorizedSession(storedResult.token, storedResult.state);
});

authChannel?.addEventListener("message", (event) => {
  if (event.data?.type !== "dquery.accountAuthorized") return;
  finishAuthorizedSession(event.data.token, event.data.state);
});

button?.addEventListener("click", startAuthorize);
