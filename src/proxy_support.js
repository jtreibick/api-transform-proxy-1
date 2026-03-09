function createProxySupportApi({ HttpError, getStoredContentType, isPlainObject, safeMetaHeaders }) {
  function getEnvInt(env, key, fallback) {
    const raw = env[key];
    if (raw === undefined || raw === null || raw === "") return fallback;
    const n = Number(raw);
    return Number.isFinite(n) ? n : fallback;
  }

  function concatUint8Arrays(chunks) {
    const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.byteLength;
    }
    return out;
  }

  async function readJsonWithLimit(request, maxBytes) {
    const reader = request.body?.getReader();
    if (!reader) {
      throw new HttpError(400, "EMPTY_BODY", "Request body is required");
    }

    let total = 0;
    const chunks = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new HttpError(413, "REQUEST_TOO_LARGE", `Request body exceeds ${maxBytes} bytes`);
      }
      chunks.push(value);
    }

    if (total === 0) {
      throw new HttpError(400, "EMPTY_BODY", "Request body is required");
    }

    const text = new TextDecoder().decode(concatUint8Arrays(chunks));
    try {
      return JSON.parse(text);
    } catch {
      throw new HttpError(400, "INVALID_JSON", "Request body must be valid JSON");
    }
  }

  async function readTextWithLimit(request, maxBytes) {
    const reader = request.body?.getReader();
    if (!reader) {
      throw new HttpError(400, "EMPTY_BODY", "Request body is required");
    }

    let total = 0;
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new HttpError(413, "REQUEST_TOO_LARGE", `Request body exceeds ${maxBytes} bytes`);
      }
      chunks.push(value);
    }

    if (total === 0) {
      throw new HttpError(400, "EMPTY_BODY", "Request body is required");
    }
    return new TextDecoder().decode(concatUint8Arrays(chunks));
  }

  function truncateJsonSnippet(value, maxLen = 1200) {
    let text;
    try {
      text = JSON.stringify(value);
    } catch {
      text = String(value);
    }
    if (text.length <= maxLen) return text;
    return `${text.slice(0, maxLen)}...(truncated)`;
  }

  function enforceInvokeContentType(request) {
    const contentType = getStoredContentType(request.headers);
    if (!contentType.includes("application/json")) {
      throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json");
    }
  }

  function validateInvokePayload(payload, { allowMissingUrl = false } = {}) {
    const problems = [];

    if (!isPlainObject(payload)) {
      problems.push("payload must be a JSON object");
      return problems;
    }

    if (!isPlainObject(payload.upstream)) {
      problems.push("payload.upstream is required and must be an object");
      return problems;
    }

    const { upstream } = payload;

    if (typeof upstream.method !== "string") {
      problems.push("upstream.method is required and must be a string");
    } else {
      const m = upstream.method.toUpperCase();
      if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(m)) {
        problems.push("upstream.method must be one of GET, POST, PUT, PATCH, DELETE");
      }
    }

    if (!allowMissingUrl && (typeof upstream.url !== "string" || upstream.url.trim() === "")) {
      problems.push("upstream.url is required and must be a non-empty string");
    } else if (upstream.url !== undefined && (typeof upstream.url !== "string" || upstream.url.trim() === "")) {
      problems.push("upstream.url must be a non-empty string when provided");
    }

    if (upstream.headers !== undefined && !isPlainObject(upstream.headers)) {
      problems.push("upstream.headers must be an object when provided");
    }

    if (upstream.auth_profile !== undefined && typeof upstream.auth_profile !== "string") {
      problems.push("upstream.auth_profile must be a string when provided");
    }

    if (upstream.body !== undefined) {
      if (!isPlainObject(upstream.body)) {
        problems.push("upstream.body must be an object when provided");
      } else {
        const bodyType = String(upstream.body.type || "none").toLowerCase();
        if (!["none", "json", "urlencoded", "raw"].includes(bodyType)) {
          problems.push("upstream.body.type must be one of none, json, urlencoded, raw");
        }
        if (bodyType === "raw" && upstream.body.raw !== undefined && typeof upstream.body.raw !== "string") {
          problems.push("upstream.body.raw must be a string for body.type=raw");
        }
        if (bodyType === "urlencoded") {
          const rawOk = upstream.body.raw === undefined || typeof upstream.body.raw === "string";
          const valOk = upstream.body.value === undefined || isPlainObject(upstream.body.value);
          if (!rawOk || !valOk) {
            problems.push("upstream.body for urlencoded must use raw:string or value:object");
          }
        }
      }
    }

    return problems;
  }

  function isIpLiteral(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  }

  function isPrivateOrLinkLocalIp(ip) {
    const parts = ip.split(".").map((x) => Number(x));
    if (parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return false;

    const [a, b] = parts;
    if (a === 10 || a === 127) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }

  function assertSafeUpstreamUrl(urlLike, allowedHosts) {
    const u = urlLike instanceof URL ? urlLike : new URL(urlLike);

    if (u.protocol !== "https:") {
      throw new HttpError(400, "UPSTREAM_PROTOCOL_NOT_ALLOWED", "Upstream URL must use https");
    }

    const hostname = u.hostname.toLowerCase();

    if (allowedHosts && !allowedHosts.has(hostname)) {
      throw new HttpError(
        403,
        "UPSTREAM_HOST_NOT_ALLOWED",
        `Upstream host not allowlisted: ${hostname}`,
        { allowed_hosts_hint: "Set ALLOWED_HOSTS with a comma-separated host allowlist." }
      );
    }

    if (hostname === "localhost" || hostname.endsWith(".localhost")) {
      throw new HttpError(403, "UPSTREAM_HOST_BLOCKED", "localhost is blocked");
    }

    if (isIpLiteral(hostname)) {
      if (isPrivateOrLinkLocalIp(hostname) || hostname === "169.254.169.254") {
        throw new HttpError(403, "UPSTREAM_IP_BLOCKED", "Private/link-local IPs are blocked");
      }
    }

    return u;
  }

  function detectResponseType(contentType) {
    const ct = String(contentType || "").toLowerCase();
    if (!ct) return "binary";
    if (ct.includes("application/json") || ct.includes("+json")) return "json";
    if (ct.startsWith("text/")) return "text";
    if (ct.includes("xml") || ct.includes("javascript")) return "text";
    return "binary";
  }

  async function readResponseWithLimit(resp, maxBytes) {
    const reader = resp.body?.getReader();
    if (!reader) return new Uint8Array();

    let total = 0;
    const chunks = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new HttpError(413, "RESPONSE_TOO_LARGE", `Upstream response exceeds ${maxBytes} bytes`);
      }
      chunks.push(value);
    }

    return concatUint8Arrays(chunks);
  }

  function decodeBody(buffer) {
    return new TextDecoder().decode(buffer);
  }

  function parseJsonOrNull(text) {
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  function toSafeUpstreamHeaders(headers) {
    const out = {};
    for (const [k, v] of headers.entries()) {
      if (safeMetaHeaders.has(k.toLowerCase())) out[k.toLowerCase()] = v;
    }
    return out;
  }

  function normalizeHostInput(raw) {
    const input = String(raw || "").trim();
    if (!input) {
      throw new HttpError(400, "INVALID_HOST", "host is required");
    }

    try {
      const u = new URL(input);
      if (u.protocol !== "https:") {
        throw new HttpError(400, "INVALID_HOST", "host URL must use https");
      }
      return u.hostname.toLowerCase();
    } catch {
      if (!/^[a-z0-9.-]+$/i.test(input)) {
        throw new HttpError(400, "INVALID_HOST", "host must be a valid hostname or https URL");
      }
      return input.toLowerCase();
    }
  }

  function parseProxyHostBaseUrl(proxyHostHeader) {
    const raw = String(proxyHostHeader || "").trim();
    if (!raw) return null;

    try {
      const url = new URL(raw);
      if (url.protocol !== "https:") {
        throw new HttpError(400, "UPSTREAM_PROTOCOL_NOT_ALLOWED", "Configured upstream host must use https");
      }
      return `${url.protocol}//${url.host}`;
    } catch {
      const host = normalizeHostInput(raw);
      return `https://${host}`;
    }
  }

  function resolveUpstreamUrl(rawUrl, proxyHostHeader) {
    const base = parseProxyHostBaseUrl(proxyHostHeader);
    const urlText = typeof rawUrl === "string" ? rawUrl.trim() : "";

    if (!base) {
      if (!urlText) {
        throw new HttpError(400, "INVALID_REQUEST", "upstream.url is required");
      }
      return new URL(urlText);
    }

    if (!urlText) return new URL(base);

    try {
      const absolute = new URL(urlText);
      return new URL(`${absolute.pathname}${absolute.search}${absolute.hash}`, base);
    } catch {
      return new URL(urlText, base);
    }
  }

  return {
    getEnvInt,
    readJsonWithLimit,
    readTextWithLimit,
    truncateJsonSnippet,
    enforceInvokeContentType,
    validateInvokePayload,
    assertSafeUpstreamUrl,
    isIpLiteral,
    detectResponseType,
    readResponseWithLimit,
    decodeBody,
    parseJsonOrNull,
    toSafeUpstreamHeaders,
    resolveUpstreamUrl,
  };
}

export { createProxySupportApi };
