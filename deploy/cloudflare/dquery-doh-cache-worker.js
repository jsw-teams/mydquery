const DOH_PATH = /^\/dns-query$/;
const RESOLVER_DOH_PATH = /^\/dns-query\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const inflight = new Map();

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event));
});

async function handleRequest(event) {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || (!DOH_PATH.test(url.pathname) && !RESOLVER_DOH_PATH.test(url.pathname))) {
    return fetch(request);
  }

  const dnsParam = url.searchParams.get("dns") || "";
  const queryBytes = decodeBase64URL(dnsParam);
  if (!queryBytes || queryBytes.length < 2) {
    return fetch(request);
  }
  const question = parseDNSQuestion(queryBytes);
  if (!question) {
    return fetch(request);
  }

  const requestID = queryBytes.slice(0, 2);
  const rd = (queryBytes[2] & 0x01) === 0x01 ? "1" : "0";
  const cd = (queryBytes[3] & 0x10) === 0x10 ? "1" : "0";

  const cacheURL = new URL(request.url);
  cacheURL.search = "";
  cacheURL.searchParams.set("name", question.name);
  cacheURL.searchParams.set("type", String(question.type));
  cacheURL.searchParams.set("class", String(question.qclass));
  cacheURL.searchParams.set("rd", rd);
  cacheURL.searchParams.set("cd", cd);
  cacheURL.searchParams.set("do", question.dnssecOK ? "1" : "0");
  cacheURL.searchParams.set("accept", acceptsDNSMessage(request) ? "dns-message" : "");
  cacheURL.searchParams.set("ecs", request.headers.get("x-ecs") || "");
  if (DOH_PATH.test(url.pathname)) {
    cacheURL.searchParams.set("country", request.cf && request.cf.country ? request.cf.country : request.headers.get("cf-ipcountry") || "");
  }

  const cacheRequest = new Request(cacheURL.toString(), { method: "GET" });
  const cache = caches.default;
  const cached = await cache.match(cacheRequest);
  if (cached) {
    return responseWithRequestID(cached, requestID, "HIT");
  }

  const inflightKey = cacheRequest.url;
  if (inflight.has(inflightKey)) {
    const coalesced = await inflight.get(inflightKey);
    if (coalesced && coalesced.cacheResponse) {
      return responseWithRequestID(coalesced.cacheResponse.clone(), requestID, "COALESCED");
    }
  }

  const fillPromise = fillCache(event, request, cacheRequest, cache, url, requestID);
  inflight.set(inflightKey, fillPromise);
  let filled;
  try {
    filled = await fillPromise;
  } finally {
    inflight.delete(inflightKey);
  }
  if (!filled || !filled.cacheResponse) {
    return filled ? filled.clientResponse : fetch(request);
  }

  return responseWithRequestID(filled.clientResponse, requestID, "MISS");
}

async function fillCache(event, request, cacheRequest, cache, url, requestID) {
  const originResponse = await fetch(request);
  if (!isCacheableDNSResponse(originResponse)) {
    logRequest(request, url, "BYPASS", originResponse.status);
    return { clientResponse: originResponse, cacheResponse: null };
  }

  const originBytes = new Uint8Array(await originResponse.arrayBuffer());
  const clientBytes = originBytes.slice();
  const cachedBytes = originBytes.slice();
  if (clientBytes.length >= 2) {
    clientBytes[0] = requestID[0];
    clientBytes[1] = requestID[1];
    cachedBytes[0] = 0;
    cachedBytes[1] = 0;
  }

  const cacheHeaders = new Headers(originResponse.headers);
  cacheHeaders.set("X-DQuery-Worker-Cache", "MISS");
  cacheHeaders.delete("Set-Cookie");
  const clientHeaders = new Headers(cacheHeaders);

  const cacheResponse = new Response(cachedBytes, {
    status: originResponse.status,
    statusText: originResponse.statusText,
    headers: cacheHeaders
  });
  event.waitUntil(cache.put(cacheRequest, cacheResponse.clone()));

  logRequest(request, url, "MISS", originResponse.status);
  const clientResponse = new Response(clientBytes, {
    status: originResponse.status,
    statusText: originResponse.statusText,
    headers: clientHeaders
  });
  return { clientResponse, cacheResponse };
}

function parseDNSQuestion(bytes) {
  if (bytes.length < 18) {
    return null;
  }
  const qdcount = readUint16(bytes, 4);
  if (qdcount !== 1) {
    return null;
  }
  let offset = 12;
  const labels = [];
  let ended = false;
  for (let i = 0; i < 128; i += 1) {
    if (offset >= bytes.length) {
      return null;
    }
    const length = bytes[offset];
    if (length === 0) {
      offset += 1;
      ended = true;
      break;
    }
    if ((length & 0xc0) !== 0 || length > 63 || offset + 1 + length > bytes.length) {
      return null;
    }
    let label = "";
    for (let j = 0; j < length; j += 1) {
      label += String.fromCharCode(bytes[offset + 1 + j]);
    }
    labels.push(label.toLowerCase());
    offset += 1 + length;
  }
  if (!ended) {
    return null;
  }
  if (offset + 4 > bytes.length) {
    return null;
  }
  const type = readUint16(bytes, offset);
  const qclass = readUint16(bytes, offset + 2);
  return {
    name: labels.length ? `${labels.join(".")}.` : ".",
    type,
    qclass,
    dnssecOK: hasDNSSECOK(bytes, offset + 4)
  };
}

function hasDNSSECOK(bytes, offset) {
  const arcount = readUint16(bytes, 10);
  let cursor = offset;
  for (let i = 0; i < arcount; i += 1) {
    if (cursor >= bytes.length) {
      return false;
    }
    const nameLength = bytes[cursor];
    if ((nameLength & 0xc0) !== 0 || cursor + 1 + nameLength + 10 > bytes.length) {
      return false;
    }
    cursor += 1 + nameLength;
    const rrtype = readUint16(bytes, cursor);
    const ttlLow = readUint16(bytes, cursor + 6);
    const rdlength = readUint16(bytes, cursor + 8);
    cursor += 10;
    if (cursor + rdlength > bytes.length) {
      return false;
    }
    if (rrtype === 41 && (ttlLow & 0x8000) === 0x8000) {
      return true;
    }
    cursor += rdlength;
  }
  return false;
}

function readUint16(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function logRequest(request, url, cacheStatus, status) {
  console.log(JSON.stringify({
    event: "dquery_doh_cache",
    cache: cacheStatus,
    status: status || 200,
    path_type: DOH_PATH.test(url.pathname) ? "public" : "resolver",
    country: request.cf && request.cf.country ? request.cf.country : "",
    colo: request.cf && request.cf.colo ? request.cf.colo : ""
  }));
}

function acceptsDNSMessage(request) {
  const accept = request.headers.get("accept") || "";
  return accept.toLowerCase().includes("application/dns-message") || accept.trim() === "" || accept.includes("*/*");
}

function isCacheableDNSResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  return response.status === 200 && contentType.toLowerCase().includes("application/dns-message");
}

async function responseWithRequestID(response, requestID, cacheStatus) {
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length >= 2) {
    bytes[0] = requestID[0];
    bytes[1] = requestID[1];
  }
  const headers = new Headers(response.headers);
  headers.set("X-DQuery-Worker-Cache", cacheStatus);
  headers.delete("Set-Cookie");
  return new Response(bytes, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function decodeBase64URL(value) {
  try {
    let normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const remainder = normalized.length % 4;
    if (remainder === 2) {
      normalized += "==";
    } else if (remainder === 3) {
      normalized += "=";
    } else if (remainder === 1) {
      return null;
    }
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}
