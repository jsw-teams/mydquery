const lang = navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";

const text = {
  en: {
    kicker: "Account DNS",
    title: "Sign in to DNS Console",
    copy: "Sign in through JS.Gripe Account Center. After authorization, you will return to this DNS console.",
    submit: "Open sign-in",
    back: "Back to public lookup",
    failed: "Sign-in was not completed. Try again.",
    retry: "Sign-in was not completed. Try again."
  },
  zh: {
    kicker: "账户 DNS",
    title: "登录个人 DNS 控制台",
    copy: "通过技诉账户中心完成登录，授权成功后会回到 DNS 控制台。",
    submit: "打开登录",
    back: "返回公共查询",
    failed: "登录未完成，请重试。",
    retry: "登录未完成，请重新尝试。"
  }
};

document.querySelectorAll("[data-i18n]").forEach((node) => {
  const value = text[lang][node.dataset.i18n];
  if (value) node.textContent = value;
});

const button = document.querySelector("#login-button");
const status = document.querySelector("#login-status");
const params = new URLSearchParams(window.location.search);

function setStatus(message, tone = "") {
  if (!status) return;
  status.textContent = message;
  status.dataset.tone = tone;
}

function showError(message) {
  setStatus(message || text[lang].failed, "bad");
}

if (params.get("error")) {
  showError(text[lang].retry);
}

button?.addEventListener("click", () => {
  setStatus("", "");
  const popup = window.open("/auth/account/start?popup=1", "dqueryAccountLogin", "popup=yes,width=520,height=720");
  if (!popup) {
    window.location.href = "/auth/account/start?popup=1";
    return;
  }
  const timer = window.setInterval(() => {
    if (popup.closed) window.clearInterval(timer);
  }, 700);
});

window.addEventListener("message", (event) => {
  if (event.origin !== window.location.origin) return;
  const payload = event.data || {};
  if (payload.source !== "dquery-auth") return;
  if (payload.status === "ok") {
    window.location.href = payload.redirectTo || "/console/";
    return;
  }
  showError(payload.message);
});
