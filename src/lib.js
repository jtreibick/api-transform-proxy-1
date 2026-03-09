export class HttpError extends Error {
  constructor(status, code, message, details = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function toHttpError(error) {
  if (error instanceof HttpError) return error;
  return new HttpError(
    500,
    "INTERNAL_ERROR",
    "Unhandled Worker error",
    { cause: String(error?.message || error) }
  );
}

export function successEnvelope(data, meta = {}) {
  return { ok: true, data, meta };
}

export function errorEnvelope(code, message, details, meta = {}) {
  const error = { code, message };
  if (details !== undefined && details !== null) error.details = details;
  const out = { error };
  if (meta && Object.keys(meta).length > 0) out.meta = meta;
  return out;
}

export function jsonResponse(status, body, extraHeaders = null) {
  const headers = {
    "content-type": "application/json; charset=utf-8",
  };
  if (extraHeaders && typeof extraHeaders === "object") {
    for (const [k, v] of Object.entries(extraHeaders)) {
      if (!k || v === undefined || v === null) continue;
      headers[k] = String(v);
    }
  }
  return new Response(JSON.stringify(body), {
    status,
    headers,
  });
}

export function apiError(status, code, message, details = null, meta = null) {
  return jsonResponse(status, errorEnvelope(code, message, details, meta || {}));
}

export function isNonArrayObject(v) {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

export function isPlainObject(v) {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

export function normalizeHeaderName(name) {
  return String(name || "").trim().toLowerCase();
}

export function getPathValue(obj, path) {
  const p = String(path || "").trim();
  if (!p) return null;
  const parts = p.split(".");
  let cur = obj;
  for (const part of parts) {
    if (!part) continue;
    if (!isNonArrayObject(cur) && !Array.isArray(cur)) return null;
    if (!(part in cur)) return null;
    cur = cur[part];
  }
  return cur;
}

export function getStoredContentType(headers) {
  return (headers.get("content-type") || "").toLowerCase();
}

export function looksJson(contentType) {
  return contentType.includes("application/json") || contentType.includes("+json");
}

export function looksYaml(contentType) {
  return (
    contentType.includes("text/yaml") ||
    contentType.includes("application/yaml") ||
    contentType.includes("application/x-yaml") ||
    contentType.includes("text/x-yaml")
  );
}

export function normalizeHeaderMap(headersLike) {
  const out = {};
  if (!headersLike) return out;
  if (headersLike instanceof Headers) {
    for (const [k, v] of headersLike.entries()) out[k.toLowerCase()] = v;
    return out;
  }
  if (isNonArrayObject(headersLike)) {
    for (const [k, v] of Object.entries(headersLike)) out[String(k).toLowerCase()] = String(v);
  }
  return out;
}
