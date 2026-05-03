const script = document.currentScript;
const endpoint = script?.dataset.endpoint || "https://gateway.js.gripe/api/v1/dquery";
const isEn = script?.dataset.lang === "en";

const typeCodes = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  NAPTR: 35,
  SRV: 33,
  DS: 43,
  DNSKEY: 48,
  TLSA: 52,
  SVCB: 64,
  HTTPS: 65,
  CAA: 257
};

const typeNames = Object.fromEntries(Object.entries(typeCodes).map(([name, code]) => [code, name]));
const rcodeNames = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED"
};

const lookupEl = document.querySelector(".lookup");
const form = document.querySelector("#dns-form");
const domainInput = document.querySelector("#domain");
const typeInput = document.querySelector("#record-type");
const resultPanel = document.querySelector("#result-panel");
const resultTitle = document.querySelector("#result-title");
const jsonResult = document.querySelector("#json-result");
const cacheFlushButton = document.querySelector("#cache-flush");

function normalizeName(name) {
  return name.trim().replace(/\.$/, "");
}

function typeComment(type) {
  const name = typeNames[type];
  return name ? `${type} /* ${name} */` : `${type}`;
}

function encodeName(name) {
  const labels = normalizeName(name).split(".").filter(Boolean);
  const bytes = [];
  for (const label of labels) {
    const encoded = new TextEncoder().encode(label);
    if (encoded.length > 63) {
      throw new Error("label_too_long");
    }
    bytes.push(encoded.length, ...encoded);
  }
  bytes.push(0);
  return bytes;
}

function buildQuery(name, type) {
  const id = crypto.getRandomValues(new Uint16Array(1))[0];
  const qname = encodeName(name);
  const message = new Uint8Array(12 + qname.length + 4);
  const view = new DataView(message.buffer);

  view.setUint16(0, id);
  view.setUint16(2, 0x0100);
  view.setUint16(4, 1);
  view.setUint16(6, 0);
  view.setUint16(8, 0);
  view.setUint16(10, 0);
  message.set(qname, 12);
  view.setUint16(12 + qname.length, typeCodes[type]);
  view.setUint16(12 + qname.length + 2, 1);

  return message;
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function readName(view, offset, depth = 0) {
  if (depth > 12) {
    throw new Error("dns_name_pointer_loop");
  }

  const labels = [];
  let cursor = offset;
  let nextOffset = offset;
  let jumped = false;

  while (true) {
    const length = view.getUint8(cursor);
    if (length === 0) {
      cursor += 1;
      if (!jumped) {
        nextOffset = cursor;
      }
      break;
    }

    if ((length & 0xc0) === 0xc0) {
      const pointer = ((length & 0x3f) << 8) | view.getUint8(cursor + 1);
      const nested = readName(view, pointer, depth + 1);
      labels.push(nested.name);
      cursor += 2;
      if (!jumped) {
        nextOffset = cursor;
      }
      jumped = true;
      break;
    }

    cursor += 1;
    const bytes = new Uint8Array(view.buffer, view.byteOffset + cursor, length);
    labels.push(new TextDecoder().decode(bytes));
    cursor += length;
  }

  return { name: labels.filter(Boolean).join(".") + ".", offset: nextOffset };
}

function parseIPv6(view, offset) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(view.getUint16(offset + i).toString(16));
  }

  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < parts.length; i += 1) {
    if (parts[i] !== "0") {
      continue;
    }
    let j = i;
    while (j < parts.length && parts[j] === "0") {
      j += 1;
    }
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen > 1) {
    parts.splice(bestStart, bestLen, "");
    if (bestStart === 0) {
      parts.unshift("");
    }
    if (bestStart + bestLen === 8) {
      parts.push("");
    }
  }
  return parts.join(":");
}

function parseRdata(view, type, offset, length) {
  if (type === typeCodes.A && length === 4) {
    return Array.from(new Uint8Array(view.buffer, view.byteOffset + offset, length)).join(".");
  }
  if (type === typeCodes.AAAA && length === 16) {
    return parseIPv6(view, offset);
  }
  if ([typeCodes.NS, typeCodes.CNAME, typeCodes.PTR].includes(type)) {
    return readName(view, offset).name;
  }
  if (type === typeCodes.MX) {
    return `${view.getUint16(offset)} ${readName(view, offset + 2).name}`;
  }
  if (type === typeCodes.TXT) {
    const chunks = [];
    let cursor = offset;
    const end = offset + length;
    while (cursor < end) {
      const chunkLength = view.getUint8(cursor);
      cursor += 1;
      const bytes = new Uint8Array(view.buffer, view.byteOffset + cursor, chunkLength);
      chunks.push(new TextDecoder().decode(bytes));
      cursor += chunkLength;
    }
    return chunks.join(" ");
  }
  return Array.from(new Uint8Array(view.buffer, view.byteOffset + offset, length))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function parseRecords(view, count, offset) {
  const records = [];
  let cursor = offset;
  for (let i = 0; i < count; i += 1) {
    const name = readName(view, cursor);
    cursor = name.offset;
    const type = view.getUint16(cursor);
    const klass = view.getUint16(cursor + 2);
    const ttl = view.getUint32(cursor + 4);
    const rdlength = view.getUint16(cursor + 8);
    cursor += 10;
    const data = parseRdata(view, type, cursor, rdlength);
    cursor += rdlength;
    records.push({ name: name.name, type, class: klass, TTL: ttl, data });
  }
  return { records, offset: cursor };
}

function parseResponse(buffer) {
  const view = new DataView(buffer);
  const flags = view.getUint16(2);
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);
  const nscount = view.getUint16(8);
  const arcount = view.getUint16(10);
  let offset = 12;

  const questions = [];
  for (let i = 0; i < qdcount; i += 1) {
    const qname = readName(view, offset);
    offset = qname.offset;
    const type = view.getUint16(offset);
    const klass = view.getUint16(offset + 2);
    offset += 4;
    questions.push({ name: qname.name, type, class: klass });
  }

  const answer = parseRecords(view, ancount, offset);
  const authority = parseRecords(view, nscount, answer.offset);
  const additional = parseRecords(view, arcount, authority.offset);

  return {
    Status: flags & 0x000f,
    TC: Boolean(flags & 0x0200),
    RD: Boolean(flags & 0x0100),
    RA: Boolean(flags & 0x0080),
    AD: Boolean(flags & 0x0020),
    CD: Boolean(flags & 0x0010),
    Question: questions,
    Answer: answer.records,
    Authority: authority.records,
    Additional: additional.records
  };
}

function dnsJsonString(payload) {
  const json = JSON.stringify(payload, null, 2);
  return json
    .replace(/"Status": (\d+)/, (_, code) => `"Status": ${code} /* ${rcodeNames[Number(code)] || "RCODE"} */`)
    .replace(/"type": (\d+)/g, (_, type) => `"type": ${typeComment(Number(type))}`);
}

function showResult(name, type, text) {
  lookupEl.classList.add("has-result");
  resultPanel.hidden = false;
  resultTitle.textContent = isEn ? `Result for ${name}/${type}:` : `${name}/${type} 查询结果：`;
  jsonResult.textContent = text;
}

async function resolveName(name, type) {
  const dnsMessage = buildQuery(name, type);
  const response = await fetch(`${endpoint}?dns=${base64url(dnsMessage)}`, {
    headers: { Accept: "application/dns-message" },
    cache: "no-store"
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `HTTP ${response.status}`);
  }
  return parseResponse(await response.arrayBuffer());
}

function syncUrl(name, type) {
  const url = new URL(window.location.href);
  url.searchParams.set("name", name);
  url.searchParams.set("type", type);
  window.history.replaceState({}, "", url);
}

async function flushBrowserCache() {
  cacheFlushButton.disabled = true;
  cacheFlushButton.textContent = isEn ? "Flushing..." : "正在刷新...";
  try {
    if ("caches" in window) {
      const names = await caches.keys();
      await Promise.all(names.map((name) => caches.delete(name)));
    }
    localStorage.clear();
    sessionStorage.clear();
  } finally {
    const url = new URL(window.location.href);
    url.searchParams.set("cache", String(Date.now()));
    window.location.replace(url);
  }
}

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = normalizeName(domainInput.value);
  const type = typeInput.value;
  if (!name) {
    showResult("?", type, JSON.stringify({ error: isEn ? "DNS Name is required" : "请填写 DNS 名称" }, null, 2));
    return;
  }

  showResult(name, type, isEn ? "Resolving..." : "查询中...");
  syncUrl(name, type);

  try {
    const payload = await resolveName(name, type);
    showResult(name, type, dnsJsonString(payload));
  } catch (error) {
    showResult(name, type, JSON.stringify({ error: error instanceof Error ? error.message : "query_failed" }, null, 2));
  }
});

cacheFlushButton?.addEventListener("click", flushBrowserCache);

const params = new URLSearchParams(window.location.search);
const initialName = normalizeName(params.get("name") || "");
const initialType = params.get("type")?.toUpperCase() || "A";
if (initialType in typeCodes) {
  typeInput.value = initialType;
}
if (initialName) {
  domainInput.value = initialName;
  form.requestSubmit();
}
