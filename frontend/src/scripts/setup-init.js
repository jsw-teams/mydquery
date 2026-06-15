const lang = navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";

const text = {
  en: {
    kicker: "dquery setup",
    title: "Create system administrator",
    copy: "Setup is only available before any local user exists. The first account becomes system_admin.",
    email: "Email",
    displayName: "Display name",
    password: "Password",
    submit: "Finish setup",
    already: "dquery is already initialized. Redirecting to login.",
    failed: "Setup failed. Use a valid email and a password with at least 10 characters."
  },
  zh: {
    kicker: "dquery 初始化",
    title: "创建首个系统管理员",
    copy: "初始化只允许在没有本地用户时执行。首个账户会成为 system_admin。",
    email: "邮箱",
    displayName: "显示名",
    password: "密码",
    submit: "完成初始化",
    already: "dquery 已初始化，正在转到登录页。",
    failed: "初始化失败，请使用有效邮箱和至少 10 位密码。"
  }
};

document.querySelectorAll("[data-i18n]").forEach((node) => {
  const value = text[lang][node.dataset.i18n];
  if (value) node.textContent = value;
});

const form = document.querySelector("#setup-form");
const email = document.querySelector("#setup-email");
const displayName = document.querySelector("#setup-display-name");
const password = document.querySelector("#setup-password");
const status = document.querySelector("#setup-status");

function setStatus(message, tone = "") {
  if (!status) return;
  status.textContent = message;
  status.dataset.tone = tone;
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const response = await fetch(`/api/v1/dquery${path}`, { ...options, credentials: "include", headers, cache: "no-store" });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

async function checkStatus() {
  try {
    const result = await api("/setup/status");
    if (result.initialized) {
      setStatus(text[lang].already, "ok");
      window.location.replace("/login/");
    }
  } catch {
    setStatus(text[lang].failed, "bad");
  }
}

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("", "");
  try {
    await api("/setup/init", {
      method: "POST",
      body: JSON.stringify({
        email: email?.value || "",
        display_name: displayName?.value || "",
        password: password?.value || ""
      })
    });
    window.location.replace("/console/");
  } catch {
    setStatus(text[lang].failed, "bad");
  }
});

checkStatus();
