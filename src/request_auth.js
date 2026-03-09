import { HttpError } from "./lib.js";

function escapeRegExp(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function scopedKvKey(scope, leaf) {
  const s = String(scope || "").trim();
  const l = String(leaf || "").trim();
  if (!s || !l) return null;
  if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(s) || !/^[a-zA-Z0-9_.-]{1,64}$/.test(l)) return null;
  return `${s}/${l}`;
}

function collectScopedPlaceholders(input) {
  const text = String(input || "");
  const pattern = /\$\{([a-zA-Z0-9_.-]{1,64})\}/g;
  const out = new Set();
  let match;
  while ((match = pattern.exec(text)) !== null) {
    if (match[1]) out.add(match[1]);
  }
  return [...out];
}

function formatIso(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return "";
  try {
    return new Date(n).toISOString();
  } catch {
    return "";
  }
}

function formatTimestamp(ms, format) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return "";
  if (format === "epoch_seconds") return String(Math.floor(n / 1000));
  if (format === "iso_8601") return formatIso(n);
  return String(n);
}

function createRequestAuthApi({
  isNonArrayObject,
  isPlainObject,
  getPathValue,
  authProfilePrefix,
  authProfileKvKey,
  httpSecretKvKey,
  kvGetValue,
  kvPutValue,
  authProfileFields,
}) {
  async function getOrCreateScopedKvValue(env, scope, leaf) {
    const key = scopedKvKey(scope, leaf);
    if (!key) return "";
    const existing = await kvGetValue(env, key);
    if (existing !== null && existing !== undefined) return String(existing);
    await kvPutValue(env, key, "");
    return "";
  }

  async function substituteScopedPlaceholders(value, scope, env) {
    const raw = String(value ?? "");
    const leaves = collectScopedPlaceholders(raw);
    if (!leaves.length) return raw;
    let out = raw;
    for (const leaf of leaves) {
      const kvValue = await getOrCreateScopedKvValue(env, scope, leaf);
      out = out.split(`\${${leaf}}`).join(kvValue);
    }
    return out;
  }

  async function getAuthProfileState(profile, env) {
    const prefix = authProfilePrefix(profile);
    if (!prefix) return {};
    const keys = authProfileFields.map((field) => authProfileKvKey(profile, field));
    const values = await Promise.all(keys.map((key) => (key ? kvGetValue(env, key) : Promise.resolve(null))));
    const state = {};
    authProfileFields.forEach((field, idx) => {
      state[field] = values[idx] ?? "";
    });
    return state;
  }

  async function substituteAuthPlaceholders(headers, profileName, env, tsFormat) {
    const out = { ...headers };
    const state = await getAuthProfileState(profileName, env);
    const format = tsFormat || "epoch_ms";
    const map = {
      "{{current}}": String(state.current || ""),
      "{{secondary}}": String(state.secondary || ""),
      "{{issued_at_ms}}": String(state.issued_at_ms || ""),
      "{{expires_at_ms}}": String(state.expires_at_ms || ""),
      "{{secondary_issued_at_ms}}": String(state.secondary_issued_at_ms || ""),
      "{{secondary_expires_at_ms}}": String(state.secondary_expires_at_ms || ""),
      "{{issued_at_iso}}": formatIso(state.issued_at_ms),
      "{{expires_at_iso}}": formatIso(state.expires_at_ms),
      "{{secondary_issued_at_iso}}": formatIso(state.secondary_issued_at_ms),
      "{{secondary_expires_at_iso}}": formatIso(state.secondary_expires_at_ms),
      "{{issued_at}}": formatTimestamp(state.issued_at_ms, format),
      "{{expires_at}}": formatTimestamp(state.expires_at_ms, format),
      "{{secondary_issued_at}}": formatTimestamp(state.secondary_issued_at_ms, format),
      "{{secondary_expires_at}}": formatTimestamp(state.secondary_expires_at_ms, format),
    };
    for (const [name, value] of Object.entries(out)) {
      let next = String(value ?? "");
      for (const [token, tokenValue] of Object.entries(map)) {
        if (next.includes(token)) {
          next = next.split(token).join(tokenValue);
        }
      }
      out[name] = next;
    }
    return out;
  }

  async function resolveAuthProfileHeaders(profileName, config, env) {
    const name = String(profileName || "").trim();
    if (!name) return {};
    const profiles = isNonArrayObject(config?.http_auth?.profiles) ? config.http_auth.profiles : {};
    const profile = isNonArrayObject(profiles?.[name]) ? profiles[name] : null;
    if (!profile) return {};
    const headers = isNonArrayObject(profile.headers) ? profile.headers : {};
    const out = {};
    for (const [k, v] of Object.entries(headers)) {
      const key = String(k || "").trim();
      if (!key) continue;
      out[key] = String(v ?? "");
    }
    const tsFormat = profile.timestamp_format || "epoch_ms";
    return substituteAuthPlaceholders(out, name, env, tsFormat);
  }

  async function resolveStaticAuthHeaders(authConfig, env) {
    const out = {};
    const source = isNonArrayObject(authConfig?.headers) ? authConfig.headers : {};
    for (const [k, v] of Object.entries(source)) {
      const key = String(k || "").trim();
      if (!key) continue;
      out[key] = String(v ?? "");
    }
    const secretRef = String(authConfig?.secret_ref || "").trim();
    if (!secretRef) return out;
    const secretKvKey = httpSecretKvKey(secretRef);
    if (!secretKvKey) {
      throw new HttpError(400, "INVALID_CONFIG", "http_authorization.static.secret_ref is invalid");
    }
    const secretValue = await kvGetValue(env, secretKvKey);
    if (!secretValue) {
      throw new HttpError(503, "MISSING_HTTP_AUTH_SECRET", "Referenced static auth secret is not set in KV", {
        secret_ref: secretRef,
      });
    }
    const patternCurly = new RegExp(`{{\\s*${escapeRegExp(secretRef)}\\s*}}`, "g");
    const patternDollar = new RegExp(`\\$\\{\\s*${escapeRegExp(secretRef)}\\s*\\}`, "g");
    for (const [name, value] of Object.entries(out)) {
      out[name] = String(value).replace(patternCurly, secretValue).replace(patternDollar, secretValue);
    }
    return out;
  }

  async function buildHttpRequestInitFromModel(reqModel, scope, env) {
    const method = String(reqModel?.method || "GET").toUpperCase();
    const headers = new Headers();
    const headerMap = isNonArrayObject(reqModel?.headers) ? reqModel.headers : {};
    for (const [k, v] of Object.entries(headerMap)) {
      const name = String(k || "").trim();
      if (!name) continue;
      headers.set(name, await substituteScopedPlaceholders(String(v ?? ""), scope, env));
    }
    let body;
    if (method !== "GET" && method !== "HEAD") {
      const b = isNonArrayObject(reqModel?.body) ? reqModel.body : { type: "none" };
      const bodyType = String(b.type || "none").toLowerCase();
      if (bodyType === "json") {
        if (!headers.has("content-type")) headers.set("content-type", "application/json");
        const rawValue = b.value ?? {};
        body = await substituteScopedPlaceholders(JSON.stringify(rawValue), scope, env);
      } else if (bodyType === "urlencoded") {
        if (!headers.has("content-type")) headers.set("content-type", "application/x-www-form-urlencoded");
        const params = new URLSearchParams();
        const source = isPlainObject(b.value) ? b.value : {};
        for (const [k, v] of Object.entries(source)) params.append(k, await substituteScopedPlaceholders(String(v ?? ""), scope, env));
        body = params.toString();
      } else if (bodyType === "raw") {
        if (typeof b.content_type === "string" && b.content_type) headers.set("content-type", b.content_type);
        body = await substituteScopedPlaceholders(typeof b.raw === "string" ? b.raw : "", scope, env);
      }
    }
    return { method, headers, body };
  }

  async function maybeRunKeyRotation(authConfig, scope, env) {
    const mapping = isNonArrayObject(authConfig?.key_rotation_http_response) ? authConfig.key_rotation_http_response : {};
    const reqModel = isNonArrayObject(authConfig?.key_rotation_http_request) ? authConfig.key_rotation_http_request : null;
    if (!scope || !reqModel || Object.keys(mapping).length === 0) return;
    const authHeaders = isNonArrayObject(authConfig?.auth_headers) ? authConfig.auth_headers : {};
    const leaves = new Set();
    Object.values(authHeaders).forEach((v) => collectScopedPlaceholders(v).forEach((leaf) => leaves.add(leaf)));
    let needsRefresh = false;
    for (const leaf of leaves) {
      const value = await getOrCreateScopedKvValue(env, scope, leaf);
      if (!String(value || "").trim()) needsRefresh = true;
    }
    if (!needsRefresh) return;
    const url = String(reqModel?.url || "").trim();
    if (!url) return;
    const init = await buildHttpRequestInitFromModel(reqModel, scope, env);
    let res;
    try {
      res = await fetch(url, init);
    } catch {
      throw new HttpError(502, "UPSTREAM_FETCH_FAILED", "Key rotation request failed");
    }
    if (!res.ok) {
      throw new HttpError(502, "UPSTREAM_FETCH_FAILED", "Key rotation request returned non-2xx", { status: res.status });
    }
    let parsed;
    try {
      parsed = await res.json();
    } catch {
      throw new HttpError(422, "NON_JSON_RESPONSE", "Key rotation response must be JSON");
    }
    for (const [leafRaw, sourceRaw] of Object.entries(mapping)) {
      const leaf = String(leafRaw || "").trim();
      const source = String(sourceRaw || "").trim();
      if (!leaf || !source) continue;
      const key = scopedKvKey(scope, leaf);
      if (!key) continue;
      if (leaf === "current_token_ttl_unit") {
        await kvPutValue(env, key, source);
        continue;
      }
      const extracted = getPathValue(parsed, source);
      if (extracted === null || extracted === undefined) continue;
      await kvPutValue(env, key, String(extracted));
    }
  }

  async function resolveKeyRotationAuthHeaders(authConfig, scope, env) {
    if (!scope) return {};
    await maybeRunKeyRotation(authConfig, scope, env);
    const authHeaders = isNonArrayObject(authConfig?.auth_headers) ? authConfig.auth_headers : {};
    const out = {};
    for (const [k, v] of Object.entries(authHeaders)) {
      const name = String(k || "").trim();
      if (!name) continue;
      out[name] = await substituteScopedPlaceholders(String(v ?? ""), scope, env);
    }
    return out;
  }

  async function buildHttpRequestInit(req, config, env) {
    const method = String(req?.method || "GET").toUpperCase();
    const headers = new Headers();
    const authConfig = req?.http_authorization;
    if (authConfig && authConfig.type === "static") {
      const staticHeaders = authConfig.secret_ref
        ? await resolveStaticAuthHeaders(authConfig, env)
        : await resolveKeyRotationAuthHeaders({ auth_headers: authConfig.headers || {} }, String(req?.__kv_scope || "").trim(), env);
      for (const [k, v] of Object.entries(staticHeaders)) {
        headers.set(k, String(v ?? ""));
      }
    } else if (authConfig && authConfig.type === "key_rotation" && authConfig.profile) {
      const authHeaders = await resolveAuthProfileHeaders(authConfig.profile, config, env);
      for (const [k, v] of Object.entries(authHeaders)) {
        headers.set(k, String(v ?? ""));
      }
    } else if (authConfig && authConfig.type === "key_rotation") {
      const authHeaders = await resolveKeyRotationAuthHeaders(authConfig, String(req?.__kv_scope || "").trim(), env);
      for (const [k, v] of Object.entries(authHeaders)) {
        headers.set(k, String(v ?? ""));
      }
    } else if (req?.auth_profile) {
      const authHeaders = await resolveAuthProfileHeaders(req.auth_profile, config, env);
      for (const [k, v] of Object.entries(authHeaders)) {
        headers.set(k, String(v ?? ""));
      }
    }
    if (isNonArrayObject(req?.headers)) {
      for (const [k, v] of Object.entries(req.headers)) {
        headers.set(k, String(v ?? ""));
      }
    }
    let body;
    if (method !== "GET" && method !== "HEAD") {
      const b = isNonArrayObject(req?.body) ? req.body : { type: "none" };
      const bodyType = String(b.type || "none").toLowerCase();
      if (bodyType === "json") {
        if (!headers.has("content-type")) headers.set("content-type", "application/json");
        body = JSON.stringify(b.value ?? {});
      } else if (bodyType === "urlencoded") {
        if (!headers.has("content-type")) headers.set("content-type", "application/x-www-form-urlencoded");
        if (typeof b.raw === "string") {
          body = b.raw;
        } else {
          const params = new URLSearchParams();
          const source = isPlainObject(b.value) ? b.value : {};
          for (const [k, v] of Object.entries(source)) params.append(k, String(v));
          body = params.toString();
        }
      } else if (bodyType === "raw") {
        if (typeof b.content_type === "string" && b.content_type) {
          headers.set("content-type", b.content_type);
        }
        body = typeof b.raw === "string" ? b.raw : "";
      }
    }
    return { method, headers, body };
  }

  return {
    buildHttpRequestInit,
    resolveAuthProfileHeaders,
  };
}

export { createRequestAuthApi };
