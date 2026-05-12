const script = document.currentScript;
const clientId = script?.dataset.clientId || "dquery";
const lang = navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";

const text = {
  en: {
    kicker: "Account DNS",
    title: "Sign in to DNS Console",
    copy: "Use your JS.Gripe account. After authorization, you will return to this DNS console.",
    submit: "Sign in with JS.Gripe account",
    back: "Back to public lookup",
    failed: "Authorization failed. Please try again.",
    cancelled: "Authorization was not completed. Please sign in again.",
    popupBlocked: "Popup was blocked. Please allow popups and try again.",
    missingClient: "Missing dquery account client id."
  },
  zh: {
    kicker: "账户 DNS",
    title: "登录个人 DNS 控制台",
    copy: "使用技诉账户完成登录或注册，授权成功后会回到 DNS 控制台。",
    submit: "使用技诉账户登录",
    back: "返回公共查询",
    failed: "授权失败，请重试。",
    cancelled: "未完成授权，请重新登录。",
    popupBlocked: "登录小窗被拦截，请允许弹窗后重试。",
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
  persistAuthResult(token, returnedState);
  authChannel?.postMessage({ type: "dquery.accountAuthorized", token, state: returnedState });
  if (window.opener && window.opener !== window) {
    window.opener.postMessage({ type: "dquery.accountAuthorized", token, state: returnedState }, window.location.origin);
    window.close();
    return;
  }
  const expectedState = sessionStorage.getItem("dquery.authState") || "";
  if (returnedState !== expectedState) {
    setStatus(text[lang].failed, "bad");
    return;
  }
  sessionStorage.setItem("dquery.accountToken", token);
  sessionStorage.removeItem("dquery.authState");
  const next = sessionStorage.getItem("dquery.authNext") || "/console/";
  sessionStorage.removeItem("dquery.authNext");
  window.location.replace(next.startsWith("/") ? next : "/console/");
}

function authorizeURL(state) {
  const redirectURI = `${window.location.origin}/login/`;
  const url = new URL("https://account.js.gripe/login");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectURI);
  url.searchParams.set("scope", "accounts:read identities:resolve");
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
  const next = sessionStorage.getItem("dquery.authNext") || "/console/";
  sessionStorage.removeItem("dquery.authNext");
  window.location.replace(next.startsWith("/") ? next : "/console/");
}

function startAuthorize() {
  if (!clientId || clientId === "REPLACE_WITH_ACCOUNT_CLIENT_ID") {
    setStatus(text[lang].missingClient, "bad");
    return;
  }
  const next = params.get("next") || "/console/";
  const state = randomState();
  sessionStorage.setItem("dquery.authState", state);
  sessionStorage.setItem("dquery.authNext", next.startsWith("/") ? next : "/console/");
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
    if (!href.startsWith(`${window.location.origin}/login`)) return;
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

if (params.has("account_session")) {
  completeCallback();
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
