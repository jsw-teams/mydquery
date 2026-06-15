const script = document.currentScript;
const endpoint = script?.dataset.endpoint || "/api/v1/dquery/lookup";
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

function formatDNSName(labels) {
  const name = labels
    .map((label) => label.replace(/\.+$/g, ""))
    .filter(Boolean)
    .join(".");
  return name ? `${name}.` : ".";
}

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

  return { name: formatDNSName(labels), offset: nextOffset };
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

function bytesAt(view, offset, length) {
  return new Uint8Array(view.buffer, view.byteOffset + offset, length);
}

function hexBytes(bytes) {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64Bytes(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function svcParamKeyName(key) {
  return {
    0: "mandatory",
    1: "alpn",
    2: "no-default-alpn",
    3: "port",
    4: "ipv4hint",
    5: "ech",
    6: "ipv6hint",
    7: "dohpath",
    8: "ohttp"
  }[key] || `key${key}`;
}

function parseSVCBParam(view, key, offset, length) {
  const bytes = bytesAt(view, offset, length);
  if (key === 0) {
    const values = [];
    for (let cursor = offset; cursor + 1 < offset + length; cursor += 2) {
      values.push(svcParamKeyName(view.getUint16(cursor)));
    }
    return values.join(",");
  }
  if (key === 1) {
    const values = [];
    let cursor = offset;
    const end = offset + length;
    while (cursor < end) {
      const partLength = view.getUint8(cursor);
      cursor += 1;
      values.push(new TextDecoder().decode(bytesAt(view, cursor, partLength)));
      cursor += partLength;
    }
    return values.join(",");
  }
  if (key === 2 || key === 8) {
    return "";
  }
  if (key === 3 && length === 2) {
    return String(view.getUint16(offset));
  }
  if (key === 4 && length % 4 === 0) {
    const values = [];
    for (let cursor = offset; cursor < offset + length; cursor += 4) {
      values.push(Array.from(bytesAt(view, cursor, 4)).join("."));
    }
    return values.join(",");
  }
  if (key === 5) {
    return base64Bytes(bytes);
  }
  if (key === 6 && length % 16 === 0) {
    const values = [];
    for (let cursor = offset; cursor < offset + length; cursor += 16) {
      values.push(parseIPv6(view, cursor));
    }
    return values.join(",");
  }
  if (key === 7) {
    return new TextDecoder().decode(bytes);
  }
  return `0x${hexBytes(bytes)}`;
}

function quoteSVCBValue(value) {
  if (!value) {
    return "";
  }
  return /^[A-Za-z0-9.,:_/@%+-]+$/.test(value) ? value : JSON.stringify(value);
}

function parseSVCB(view, offset, length) {
  const end = offset + length;
  if (length < 3) {
    throw new Error("invalid_svcb_rdata");
  }
  const priority = view.getUint16(offset);
  const target = readName(view, offset + 2);
  const parts = [`${priority}`, target.name];
  let cursor = target.offset;
  while (cursor < end) {
    if (cursor + 4 > end) {
      throw new Error("invalid_svcb_param");
    }
    const key = view.getUint16(cursor);
    const paramLength = view.getUint16(cursor + 2);
    cursor += 4;
    if (cursor + paramLength > end) {
      throw new Error("invalid_svcb_param");
    }
    const name = svcParamKeyName(key);
    const value = parseSVCBParam(view, key, cursor, paramLength);
    parts.push(value ? `${name}=${quoteSVCBValue(value)}` : name);
    cursor += paramLength;
  }
  return parts.join(" ");
}

function parseRdata(view, type, offset, length) {
  const end = offset + length;
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
  if (type === typeCodes.SOA) {
    const mname = readName(view, offset);
    const rname = readName(view, mname.offset);
    const cursor = rname.offset;
    if (cursor + 20 > end) {
      throw new Error("invalid_soa_rdata");
    }
    const values = [
      view.getUint32(cursor),
      view.getUint32(cursor + 4),
      view.getUint32(cursor + 8),
      view.getUint32(cursor + 12),
      view.getUint32(cursor + 16)
    ];
    return `${mname.name} ${rname.name} ${values.join(" ")}`;
  }
  if (type === typeCodes.SRV) {
    if (length < 7) {
      throw new Error("invalid_srv_rdata");
    }
    return `${view.getUint16(offset)} ${view.getUint16(offset + 2)} ${view.getUint16(offset + 4)} ${readName(view, offset + 6).name}`;
  }
  if (type === typeCodes.CAA) {
    if (length < 2) {
      throw new Error("invalid_caa_rdata");
    }
    const flags = view.getUint8(offset);
    const tagLength = view.getUint8(offset + 1);
    if (offset + 2 + tagLength > end) {
      throw new Error("invalid_caa_rdata");
    }
    const tag = new TextDecoder().decode(new Uint8Array(view.buffer, view.byteOffset + offset + 2, tagLength));
    const value = new TextDecoder().decode(new Uint8Array(view.buffer, view.byteOffset + offset + 2 + tagLength, end - offset - 2 - tagLength));
    return `${flags} ${tag} "${value}"`;
  }
  if (type === typeCodes.DS) {
    if (length < 4) {
      throw new Error("invalid_ds_rdata");
    }
    return `${view.getUint16(offset)} ${view.getUint8(offset + 2)} ${view.getUint8(offset + 3)} ${hexBytes(bytesAt(view, offset + 4, length - 4)).toUpperCase()}`;
  }
  if (type === typeCodes.DNSKEY) {
    if (length < 4) {
      throw new Error("invalid_dnskey_rdata");
    }
    return `${view.getUint16(offset)} ${view.getUint8(offset + 2)} ${view.getUint8(offset + 3)} ${base64Bytes(bytesAt(view, offset + 4, length - 4))}`;
  }
  if (type === typeCodes.SVCB || type === typeCodes.HTTPS) {
    return parseSVCB(view, offset, length);
  }
  if (type === typeCodes.TXT) {
    const chunks = [];
    let cursor = offset;
    while (cursor < end) {
      const chunkLength = view.getUint8(cursor);
      cursor += 1;
      const bytes = new Uint8Array(view.buffer, view.byteOffset + cursor, chunkLength);
      chunks.push(new TextDecoder().decode(bytes));
      cursor += chunkLength;
    }
    return chunks.join(" ");
  }
  return hexBytes(bytesAt(view, offset, length));
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
  const payload = parseResponse(await response.arrayBuffer());
  payload.DQuery = {
    route: response.headers.get("x-dquery-route") || "",
    upstream: response.headers.get("x-dquery-upstream") || "",
    ecs: response.headers.get("x-dquery-selected-ecs") || "",
    ecsSource: response.headers.get("x-dquery-ecs-source") || "",
    cache: response.headers.get("x-dquery-cache") || ""
  };
  return payload;
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
    window.location.reload();
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
