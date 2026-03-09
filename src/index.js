import {
  htmlPage,
  escapeHtml,
  capitalize,
} from "./ui.js";
import { createCloudflareStorage } from "./internal/cloudflare/storage/index.js";
import { StorageConnectorError } from "./common/storage/interface.js";
import { PREPROCESSORS } from "./custom/preprocessors.js";
import {
  HttpError,
  toHttpError,
  successEnvelope,
  errorEnvelope,
  jsonResponse,
  apiError,
  isNonArrayObject,
  isPlainObject,
  normalizeHeaderName,
  getPathValue,
  getStoredContentType,
  looksJson,
  looksYaml,
  normalizeHeaderMap,
} from "./lib.js";
import {
  DEFAULT_CONFIG_V1,
  VALID_TRANSFORM_TYPES,
  createConfigApi,
  parseYamlConfigText,
  stringifyYamlConfig,
  validateAndNormalizeConfigV1,
} from "./config.js";
import { createRequestAuthApi } from "./request_auth.js";
import { createJwtAuthApi } from "./jwt_auth.js";
import { createKeyAuthApi } from "./key_auth.js";
import { createTransformRuntimeApi } from "./transform_runtime.js";
import { createObservabilityApi } from "./observability.js";
import { createAdminUiApi } from "./admin_ui.js";
import { createSwaggerApi } from "./swagger.js";
import { createBootstrapApi } from "./bootstrap.js";
import { createProxyRuntimeApi } from "./proxy_runtime.js";
import { createProxySupportApi } from "./proxy_support.js";
import { dispatchPublicRoute } from "./routes/public.js";
import { dispatchAdminRoute } from "./routes/admin.js";

/**
 * API transform relay for Bubble-style clients.
 *
 * Endpoints:
 * - GET /_apiproxy               : status + bootstrap page (shows created keys once)
 * - POST /_apiproxy              : bootstrap keys via JSON (one-time; returns only newly created keys)
 * - POST /_apiproxy/request      : authenticated relay + optional JSONata transform
 * - GET /_apiproxy/admin/version : build version info (admin key required)
 * - POST /_apiproxy/keys/{proxy|issuer|admin}/rotate : self-rotation using each key kind
 * - POST /_apiproxy/admin/keys/{proxy|issuer|admin}/rotate : admin override rotation
 * - GET/PUT /_apiproxy/admin/config
 * - POST /_apiproxy/admin/config/validate
 * - POST /_apiproxy/admin/config/test-rule
 * - GET/PUT/DELETE /_apiproxy/admin/debug
 * - GET /_apiproxy/admin/debug/last
 * - GET /_apiproxy/admin/live-log/stream
 * - GET /_apiproxy/admin/swagger
 * - GET /_apiproxy/admin/swagger/openapi.json
 * - PUT/DELETE /_apiproxy/admin/debug/loggingSecret
 */

const KV_PROXY_KEY = "proxy_key";
const KV_ADMIN_KEY = "admin_key";
const KV_ISSUER_KEY = "issuer_key";
const KV_PROXY_KEY_OLD = "proxy_key_old";
const KV_PROXY_KEY_OLD_EXPIRES_AT = "proxy_key_old_expires_at";
const KV_PROXY_PRIMARY_KEY_CREATED_AT = "proxy_primary_key_created_at";
const KV_PROXY_SECONDARY_KEY_CREATED_AT = "proxy_secondary_key_created_at";
const KV_ISSUER_KEY_OLD = "issuer_key_old";
const KV_ISSUER_KEY_OLD_EXPIRES_AT = "issuer_key_old_expires_at";
const KV_ISSUER_PRIMARY_KEY_CREATED_AT = "issuer_primary_key_created_at";
const KV_ISSUER_SECONDARY_KEY_CREATED_AT = "issuer_secondary_key_created_at";
const KV_ADMIN_KEY_OLD = "admin_key_old";
const KV_ADMIN_KEY_OLD_EXPIRES_AT = "admin_key_old_expires_at";
const KV_ADMIN_PRIMARY_KEY_CREATED_AT = "admin_primary_key_created_at";
const KV_ADMIN_SECONDARY_KEY_CREATED_AT = "admin_secondary_key_created_at";
const KV_CONFIG_YAML = "config_yaml_v1";
const KV_CONFIG_JSON = "config_json_v1";
const KV_ENRICHED_HEADER_PREFIX = "enriched_header:";
const KV_HTTP_SECRET_PREFIX = "http_secret:";
const KV_BOOTSTRAP_ENRICHED_HEADER_NAMES = "bootstrap_enriched_header_names_v1";
const KV_DEBUG_ENABLED_UNTIL_MS = "debug_enabled_until_ms";

const AUTH_PROFILE_PREFIXES = {
  logging: "auth/logging",
  target: "auth/target",
  jwt_inbound: "auth/jwt_inbound",
};
const AUTH_PROFILE_FIELDS = [
  "current",
  "secondary",
  "issued_at_ms",
  "expires_at_ms",
  "secondary_issued_at_ms",
  "secondary_expires_at_ms",
];
const RESERVED_ROOT = "/_apiproxy";
const ADMIN_ROOT = `${RESERVED_ROOT}/admin`;
const DEFAULT_DOCS_URL = "https://github.com/jtreibick/api-transform-proxy/blob/main/README.md";
const DEBUG_MAX_TRACE_CHARS = 32000;
const DEBUG_MAX_BODY_PREVIEW_CHARS = 4000;

const DEFAULTS = {
  ALLOWED_HOSTS: "",
  MAX_REQ_BYTES: 256 * 1024,
  MAX_RESP_BYTES: 1024 * 1024,
  MAX_EXPR_BYTES: 16 * 1024,
  TRANSFORM_TIMEOUT_MS: 400,
  ROTATE_OVERLAP_MS: 10 * 60 * 1000,
  ADMIN_ACCESS_TOKEN_TTL_SECONDS: 3600,
};

const EXPECTED_REQUEST_SCHEMA = {
  upstream: {
    method: "GET|POST|PUT|PATCH|DELETE",
    url: "/path or https://... (resolved against configured http_requests.outbound_proxy.url)",
    headers: "mapping<headerName,string> (optional)",
    auth_profile: "string (optional)",
    body: {
      type: "none|json|urlencoded|raw",
      value: "any (optional)",
      raw: "string (optional)",
      content_type: "string (optional)",
    },
  },
};

const SAFE_META_HEADERS = new Set([
  "content-type",
  "cache-control",
  "etag",
  "last-modified",
  "content-language",
  "expires",
]);
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);
const INTERNAL_AUTH_HEADERS = new Set(["x-proxy-key", "x-admin-key", "x-issuer-key"]);
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const BUILTIN_DEBUG_REDACT_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-proxy-key",
  "x-admin-key",
]);
let jsonataFactory = null;
let yamlApi = null;

function createWorker(mode = "combined") {
  const isRuntime = mode === "runtime";
  const isControl = mode === "control";
  return {
    async fetch(request, env, ctx) {
      const { pathname } = new URL(request.url);
      const normalizedPath = normalizePathname(pathname);

      try {
        const publicResponse = await dispatchPublicRoute({
          normalizedPath,
          request,
          env,
          ctx,
          reservedRoot: RESERVED_ROOT,
          handlers: routeHandlers,
          auth: routeAuth,
          options: isRuntime
            ? {
                enableRootProxy: true,
                enableStatusBootstrap: false,
                enableRequest: true,
                enableSelfRotate: true,
              }
            : isControl
              ? {
                  enableRootProxy: false,
                  enableStatusBootstrap: true,
                  enableRequest: false,
                  enableSelfRotate: false,
                }
              : undefined,
        });
        if (publicResponse) return publicResponse;

        if (!isRuntime) {
          const adminResponse = await dispatchAdminRoute({
            normalizedPath,
            request,
            env,
            adminRoot: ADMIN_ROOT,
            handlers: routeHandlers,
            auth: routeAuth,
          });
          if (adminResponse) return adminResponse;
        }

        return apiError(404, "NOT_FOUND", "Route not found");
      } catch (error) {
        return renderError(error, normalizedPath);
      }
    },
  };
}

export default createWorker("combined");

// Expose config validator for local tooling (not used by Worker runtime).
export { createWorker, validateAndNormalizeConfigV1 };

function renderError(error, pathname) {
  const err = toHttpError(error);

  if (pathname === RESERVED_ROOT && err.status >= 500) {
    return new Response(
      htmlPage(
        "Configuration error",
        `<p><b>Error:</b> ${escapeHtml(err.code)}</p>
         <p>${escapeHtml(err.message)}</p>
         <p>Fix your Worker setup and redeploy.</p>`
      ),
      { status: err.status, headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  return apiError(err.status, err.code, err.message, err.details);
}


function normalizePathname(pathname) {
  const raw = String(pathname || "/");
  if (raw === "/") return "/";
  const trimmed = raw.replace(/\/+$/, "");
  return trimmed || "/";
}

function ensureKvBinding(env) {
  const kv = kvStore(env);
  try {
    kv.assertReady();
  } catch (e) {
    if (!(e instanceof StorageConnectorError) || e.code !== "MISSING_KV_BINDING") throw e;
    throw new HttpError(
      500,
      "MISSING_KV_BINDING",
      "KV binding CONFIG is missing.",
      {
        setup: "Add [[kv_namespaces]] binding = \"CONFIG\" in wrangler.toml and redeploy.",
      }
    );
  }
}

function stateStore(env) {
  return createCloudflareStorage(env);
}

function kvStore(env) {
  return stateStore(env).keyValue;
}

async function kvGetValue(env, key) {
  return kvStore(env).get(key);
}

async function kvPutValue(env, key, value) {
  return kvStore(env).put(key, value);
}

const proxySupportApi = createProxySupportApi({
  HttpError,
  getStoredContentType,
  isPlainObject,
  safeMetaHeaders: SAFE_META_HEADERS,
});
const {
  getEnvInt,
  readJsonWithLimit,
  readTextWithLimit,
  truncateJsonSnippet,
  enforceInvokeContentType,
  validateInvokePayload,
  assertSafeUpstreamUrl,
  detectResponseType,
  readResponseWithLimit,
  decodeBody,
  parseJsonOrNull,
  toSafeUpstreamHeaders,
  resolveUpstreamUrl,
} = proxySupportApi;

const configApi = createConfigApi({
  ensureKvBinding,
  kvStore,
  kvConfigYamlKey: KV_CONFIG_YAML,
  kvConfigJsonKey: KV_CONFIG_JSON,
});

const requestAuthApi = createRequestAuthApi({
  isNonArrayObject,
  isPlainObject,
  getPathValue,
  authProfilePrefix,
  authProfileKvKey,
  httpSecretKvKey,
  kvGetValue,
  kvPutValue,
  authProfileFields: AUTH_PROFILE_FIELDS,
});

const jwtAuthApi = createJwtAuthApi({
  buildHttpRequestInit: (req, config, env) => requestAuthApi.buildHttpRequestInit(req, config, env),
  jwksCacheTtlMs: JWKS_CACHE_TTL_MS,
});

const keyAuthApi = createKeyAuthApi({
  constants: {
    KV_PROXY_KEY,
    KV_ADMIN_KEY,
    KV_ISSUER_KEY,
    KV_PROXY_KEY_OLD,
    KV_PROXY_KEY_OLD_EXPIRES_AT,
    KV_PROXY_PRIMARY_KEY_CREATED_AT,
    KV_PROXY_SECONDARY_KEY_CREATED_AT,
    KV_ISSUER_KEY_OLD,
    KV_ISSUER_KEY_OLD_EXPIRES_AT,
    KV_ISSUER_PRIMARY_KEY_CREATED_AT,
    KV_ISSUER_SECONDARY_KEY_CREATED_AT,
    KV_ADMIN_KEY_OLD,
    KV_ADMIN_KEY_OLD_EXPIRES_AT,
    KV_ADMIN_PRIMARY_KEY_CREATED_AT,
    KV_ADMIN_SECONDARY_KEY_CREATED_AT,
  },
  ensureKvBinding,
  kvStore,
  kvGetValue,
  kvPutValue,
  loadConfigV1: (env) => configApi.loadConfigV1(env),
  getEnvInt,
  defaults: DEFAULTS,
  reservedRoot: RESERVED_ROOT,
  generateSecret,
  parseMs,
  capitalize,
  escapeHtml,
  htmlPage,
  jsonResponse,
  signJwtHs256: (payload, secret) => jwtAuthApi.signJwtHs256(payload, secret),
  verifyJwtHs256: (token, secret, cfg) => jwtAuthApi.verifyJwtHs256(token, secret, cfg),
});

const transformRuntimeApi = createTransformRuntimeApi({
  isPlainObject,
  normalizeHeaderName,
  defaultHeaderForwarding: DEFAULT_CONFIG_V1.header_forwarding,
  internalAuthHeadersSet: INTERNAL_AUTH_HEADERS,
  loadJsonata,
});

const observabilityApi = createObservabilityApi({
  adminRoot: ADMIN_ROOT,
  kvDebugEnabledUntilMsKey: KV_DEBUG_ENABLED_UNTIL_MS,
  builtinDebugRedactHeaders: BUILTIN_DEBUG_REDACT_HEADERS,
  debugMaxTraceChars: DEBUG_MAX_TRACE_CHARS,
  debugMaxBodyPreviewChars: DEBUG_MAX_BODY_PREVIEW_CHARS,
  ensureKvBinding,
  kvStore,
  normalizeHeaderMap,
  loadConfigV1: (env) => configApi.loadConfigV1(env),
  getEnvInt,
  defaults: DEFAULTS,
  enforceInvokeContentType,
  readJsonWithLimit,
  jsonResponse,
  htmlPage,
  escapeHtml,
  buildHttpRequestInit: (req, config, env) => requestAuthApi.buildHttpRequestInit(req, config, env),
});

const adminUiApi = createAdminUiApi();

const swaggerApi = createSwaggerApi({
  htmlPage,
  reservedRoot: RESERVED_ROOT,
  adminRoot: ADMIN_ROOT,
});

const bootstrapApi = createBootstrapApi({
  constants: {
    kvProxyKey: KV_PROXY_KEY,
    kvAdminKey: KV_ADMIN_KEY,
    kvProxyPrimaryCreatedAt: KV_PROXY_PRIMARY_KEY_CREATED_AT,
    kvAdminPrimaryCreatedAt: KV_ADMIN_PRIMARY_KEY_CREATED_AT,
    adminRoot: ADMIN_ROOT,
    defaultDocsUrl: DEFAULT_DOCS_URL,
  },
  ensureKvBinding,
  kvGetValue,
  kvPutValue,
  kvStore,
  loadConfigV1: (env) => configApi.loadConfigV1(env),
  generateSecret,
  HttpError,
});

const proxyRuntimeApi = createProxyRuntimeApi({
  requireProxyKey,
  enforceInvokeContentType,
  readJsonWithLimit,
  getEnvInt,
  defaults: DEFAULTS,
  validateInvokePayload,
  HttpError,
  expectedRequestSchema: EXPECTED_REQUEST_SCHEMA,
  truncateJsonSnippet,
  loadConfigV1,
  defaultConfigV1: DEFAULT_CONFIG_V1,
  getDebugRedactHeaderSet,
  isDebugEnabled,
  generateSecret,
  fmtTs,
  toRedactedHeaderMap,
  previewBodyForDebug,
  resolveProxyHostForRequest,
  getInboundHeaderFilteringPolicy,
  extractJwtFromHeaders,
  verifyJwtRs256,
  getIssuerKeyState,
  verifyJwtHs256,
  resolveCustomHook,
  isPlainObject,
  normalizeHeaderMap,
  selectTransformRule,
  evalJsonataWithTimeout,
  resolveUpstreamUrl,
  getAllowedHosts,
  assertSafeUpstreamUrl,
  shouldForwardIncomingHeader,
  internalAuthHeaders: INTERNAL_AUTH_HEADERS,
  loadEnrichedHeadersMap,
  isNonArrayObject,
  resolveAuthProfileHeaders,
  signJwtHs256,
  readResponseWithLimit,
  getStoredContentType,
  decodeBody,
  detectResponseType,
  parseJsonOrNull,
  toSafeUpstreamHeaders,
  jsonResponse,
  errorEnvelope,
  successEnvelope,
  observabilityApi,
  buildHttpRequestInit: (req, config, env) => requestAuthApi.buildHttpRequestInit(req, config, env),
  validTransformTypes: VALID_TRANSFORM_TYPES,
});

function buildRuntime() {
  return {
    routeHandlers: {
      handleRootProxyRequest: (request, env, ctx) => proxyRuntimeApi.handleRootProxyRequest(request, env, ctx),
      handleStatusPage: (env, request) => bootstrapApi.handleStatusPage(env, request),
      handleBootstrapPost: (env) => bootstrapApi.handleBootstrapPost(env),
      handleRequest: (request, env, ctx) => proxyRuntimeApi.handleRequest(request, env, ctx),
      handleRotateByKind,
      handleAdminPage: () => adminUiApi.handleAdminPage(),
      handleAdminPageScriptAsset: () => adminUiApi.handleAdminPageScriptAsset(),
      handleAdminSwaggerPage: (request) => swaggerApi.handleAdminSwaggerPage(request),
      handleAdminSwaggerSpec: (request) => swaggerApi.handleAdminSwaggerSpec(request),
      handleAdminAccessTokenPost,
      handleVersion,
      handleKeysStatusGet,
      handleConfigGet,
      handleConfigPut,
      handleConfigValidate,
      handleConfigTestRule,
      handleKeyRotationConfigGet,
      handleKeyRotationConfigPut,
      handleTransformConfigGet,
      handleTransformConfigPut,
      handleDebugGet,
      handleDebugPut,
      handleDebugDelete,
      handleDebugLastGet,
      handleLiveLogStream,
      handleDebugLoggingSecretPut,
      handleDebugLoggingSecretGet,
      handleDebugLoggingSecretDelete,
      handleHttpAuthSecretRoute,
      handleHttpSecretRoute,
      handleEnrichedHeadersList,
      handleEnrichedHeaderPut,
      handleEnrichedHeaderDelete,
    },
    routeAuth: {
      requireProxyKey: (request, env) => keyAuthApi.requireProxyKey(request, env),
      requireIssuerKey: (request, env) => keyAuthApi.requireIssuerKey(request, env),
      requireAdminKey: (request, env) => keyAuthApi.requireAdminKey(request, env),
      requireAdminAuth: (request, env) => keyAuthApi.requireAdminAuth(request, env),
    },
  };
}

const { routeHandlers, routeAuth } = buildRuntime();

function getAllowedHosts(env) {
  const raw = (env.ALLOWED_HOSTS ?? DEFAULTS.ALLOWED_HOSTS).trim();
  if (!raw) return null;
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
  );
}

async function loadYamlApi() {
  if (yamlApi) return yamlApi;
  try {
    const mod = await import("yaml");
    yamlApi = {
      parse: mod.parse,
      stringify: mod.stringify,
    };
    if (typeof yamlApi.parse !== "function" || typeof yamlApi.stringify !== "function") {
      throw new Error("yaml parse/stringify not available");
    }
    return yamlApi;
  } catch (e) {
    throw new HttpError(
      500,
      "MISSING_YAML_DEPENDENCY",
      "yaml dependency is not available in this Worker build.",
      {
        setup: "Ensure yaml is listed in package.json dependencies and deploy from repository root.",
        cause: String(e?.message || e),
      }
    );
  }
}

function authProfilePrefix(name) {
  const key = String(name || "").trim();
  return AUTH_PROFILE_PREFIXES[key] || null;
}
function authProfileKvKey(profile, field) {
  const prefix = authProfilePrefix(profile);
  if (!prefix) return null;
  return `${prefix}/${field}`;
}
function isValidHttpSecretRef(ref) {
  return /^[a-zA-Z0-9_.-]{1,64}$/.test(String(ref || ""));
}
function httpSecretKvKey(ref) {
  const key = String(ref || "").trim();
  if (!isValidHttpSecretRef(key)) return null;
  return `${KV_HTTP_SECRET_PREFIX}${key}`;
}
function resolveCustomHook(name) {
  const key = String(name || "").trim();
  if (!key) return null;
  const fn = PREPROCESSORS?.[key];
  return typeof fn === "function" ? fn : null;
}

async function loadConfigV1(env) {
  return configApi.loadConfigV1(env);
}

async function loadConfigYamlV1(env) {
  return configApi.loadConfigYamlV1(env);
}

async function saveConfigFromYamlV1(yamlText, env) {
  return configApi.saveConfigFromYamlV1(yamlText, env);
}

async function saveConfigObjectV1(configObj, env) {
  return configApi.saveConfigObjectV1(configObj, env);
}

async function buildHttpRequestInit(req, config, env) {
  return requestAuthApi.buildHttpRequestInit(req, config, env);
}

async function resolveAuthProfileHeaders(profileName, config, env) {
  return requestAuthApi.resolveAuthProfileHeaders(profileName, config, env);
}

function extractJwtFromHeaders(headers, config) {
  return jwtAuthApi.extractJwtFromHeaders(headers, config);
}

async function verifyJwtHs256(token, secret, cfg) {
  return jwtAuthApi.verifyJwtHs256(token, secret, cfg);
}

async function verifyJwtRs256(token, cfg, config, env) {
  return jwtAuthApi.verifyJwtRs256(token, cfg, config, env);
}

async function signJwtHs256(payload, secret) {
  return jwtAuthApi.signJwtHs256(payload, secret);
}

function getInboundHeaderFilteringPolicy(config) {
  return transformRuntimeApi.getInboundHeaderFilteringPolicy(config);
}

function shouldForwardIncomingHeader(headerNameLower, policy) {
  return transformRuntimeApi.shouldForwardIncomingHeader(headerNameLower, policy);
}

function selectTransformRule(section, ctx) {
  return transformRuntimeApi.selectTransformRule(section, ctx);
}

function shouldRunTransform(when, status, contentType, responseBytes) {
  return transformRuntimeApi.shouldRunTransform(when, status, contentType, responseBytes);
}

async function evalJsonataWithTimeout(exprString, inputObj, timeoutMs) {
  return transformRuntimeApi.evalJsonataWithTimeout(exprString, inputObj, timeoutMs);
}

function toUpperSnakeCase(name) {
  return String(name || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[-\s]+/g, "_")
    .toUpperCase();
}

function resolveTemplateVar(varName, env) {
  const candidates = [String(varName || ""), toUpperSnakeCase(varName)];
  for (const c of candidates) {
    const v = env?.[c];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return null;
}

function resolveTemplateVars(text, env) {
  return String(text).replace(/\$\{([A-Za-z0-9_]+)\}/g, (_m, varName) => {
    const value = resolveTemplateVar(varName, env);
    if (value === null) {
      throw new HttpError(500, "MISSING_BOOTSTRAP_SECRET", "A referenced bootstrap secret variable is missing.", {
        variable: varName,
      });
    }
    return value;
  });
}

function parseBootstrapEnrichedHeadersJson(raw, env) {
  const input = String(raw || "").trim();
  if (!input) return {};

  let parsed;
  try {
    parsed = JSON.parse(input);
  } catch (e) {
    throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "BOOTSTRAP_ENRICHED_HEADERS_JSON is not valid JSON.", {
      cause: String(e?.message || e),
    });
  }
  if (!isPlainObject(parsed)) {
    throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "BOOTSTRAP_ENRICHED_HEADERS_JSON must be a JSON object.");
  }

  const out = {};
  for (const [name, value] of Object.entries(parsed)) {
    const normalized = assertValidHeaderName(name);
    if (typeof value !== "string") {
      throw new HttpError(500, "INVALID_BOOTSTRAP_HEADERS", "Each bootstrap header value must be a string.", {
        header: normalized,
      });
    }
    out[normalized] = resolveTemplateVars(value, env);
  }
  return out;
}

function getBootstrapEnrichedHeaders(env) {
  return parseBootstrapEnrichedHeadersJson(env?.BOOTSTRAP_ENRICHED_HEADERS_JSON, env);
}

async function syncBootstrapEnrichedHeaders(env, managedHeaders) {
  ensureKvBinding(env);
  const names = Object.keys(managedHeaders || {});
  const prevRaw = await kvStore(env).get(KV_BOOTSTRAP_ENRICHED_HEADER_NAMES);
  let prev = [];
  try {
    const parsed = JSON.parse(prevRaw || "[]");
    if (Array.isArray(parsed)) prev = parsed.map((n) => normalizeHeaderName(n)).filter(Boolean);
  } catch {
    prev = [];
  }
  const prevSet = new Set(prev);
  const nextSet = new Set(names);

  const deletes = [];
  for (const name of prevSet) {
    if (!nextSet.has(name)) deletes.push(kvStore(env).delete(enrichedHeaderKvKey(name)));
  }

  const gets = await Promise.all(names.map((name) => kvGetValue(env, enrichedHeaderKvKey(name))));
  const puts = [];
  for (let i = 0; i < names.length; i += 1) {
    const name = names[i];
    const desired = managedHeaders[name];
    if (gets[i] !== desired) {
      puts.push(kvPutValue(env, enrichedHeaderKvKey(name), desired));
    }
  }

  const prevSorted = [...prevSet].sort();
  const nextSorted = [...nextSet].sort();
  const namesChanged = prevSorted.length !== nextSorted.length || prevSorted.some((n, i) => n !== nextSorted[i]);
  const ops = [...deletes, ...puts];
  if (namesChanged) {
    ops.push(kvStore(env).put(KV_BOOTSTRAP_ENRICHED_HEADER_NAMES, JSON.stringify(nextSorted)));
  }
  if (ops.length > 0) {
    await Promise.all(ops);
  }
}

async function listEnrichedHeaderNames(env, managedHeaders = null) {
  ensureKvBinding(env);
  const out = [];
  let cursor = undefined;

  while (true) {
    const page = await kvStore(env).list({
      prefix: KV_ENRICHED_HEADER_PREFIX,
      cursor,
      limit: 1000,
    });
    for (const entry of page.keys || []) {
      const key = String(entry.name || "");
      if (!key.startsWith(KV_ENRICHED_HEADER_PREFIX)) continue;
      out.push(key.slice(KV_ENRICHED_HEADER_PREFIX.length));
    }
    if (!page.list_complete) {
      cursor = page.cursor;
      continue;
    }
    break;
  }

  if (managedHeaders && isPlainObject(managedHeaders)) {
    for (const name of Object.keys(managedHeaders)) out.push(name);
  }

  return [...new Set(out)].sort();
}

async function loadEnrichedHeadersMap(env) {
  const managedHeaders = getBootstrapEnrichedHeaders(env);
  await syncBootstrapEnrichedHeaders(env, managedHeaders);
  const names = await listEnrichedHeaderNames(env, managedHeaders);
  if (names.length === 0) return {};

  const values = await Promise.all(names.map((name) => kvGetValue(env, enrichedHeaderKvKey(name))));
  const out = {};
  for (let i = 0; i < names.length; i += 1) {
    const value = values[i];
    if (typeof value === "string") out[names[i]] = value;
  }
  for (const [name, value] of Object.entries(managedHeaders)) {
    out[name] = value;
  }
  return out;
}

function base64url(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function generateSecret() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

async function loadJsonata() {
  if (jsonataFactory) return jsonataFactory;

  try {
    const mod = await import("jsonata");
    jsonataFactory = mod?.default || mod;
    if (typeof jsonataFactory !== "function") {
      throw new Error("jsonata default export is not a function");
    }
    return jsonataFactory;
  } catch (e) {
    throw new HttpError(
      500,
      "MISSING_JSONATA_DEPENDENCY",
      "jsonata dependency is not available in this Worker build.",
      {
        setup: "Ensure jsonata is listed in package.json dependencies and deploy from repository root.",
        cause: String(e?.message || e),
      }
    );
  }
}

async function getProxyKey(env) {
  return keyAuthApi.getProxyKey(env);
}

async function getAdminKey(env) {
  return keyAuthApi.getAdminKey(env);
}

function keyKindConfig(kind) {
  return keyAuthApi.keyKindConfig(kind);
}

async function getKeyAuthState(kind, env) {
  return keyAuthApi.getKeyAuthState(kind, env);
}

async function requireProxyKey(request, env) {
  await keyAuthApi.requireProxyKey(request, env);
}

async function requireAdminKey(request, env) {
  await keyAuthApi.requireAdminKey(request, env);
}

async function requireIssuerKey(request, env) {
  await keyAuthApi.requireIssuerKey(request, env);
}

async function getIssuerKeyState(env) {
  return keyAuthApi.getIssuerKeyState(env);
}

async function requireKeyKind(request, env, kind) {
  await keyAuthApi.requireKeyKind(request, env, kind);
}

function getAdminAccessTokenFromRequest(request) {
  return keyAuthApi.getAdminAccessTokenFromRequest(request);
}

async function getAdminJwtSecret(env) {
  return keyAuthApi.getAdminJwtSecret(env);
}

async function validateAdminAccessToken(token, env) {
  return keyAuthApi.validateAdminAccessToken(token, env);
}

async function requireAdminAuth(request, env) {
  await keyAuthApi.requireAdminAuth(request, env);
}

async function handleAdminAccessTokenPost(env) {
  return keyAuthApi.handleAdminAccessTokenPost(env);
}

function resolveProxyHostForRequest(config) {
  let configuredTarget = "";
  const configuredRequestUrl = typeof config?.http_requests?.outbound_proxy?.url === "string"
    ? config.http_requests.outbound_proxy.url.trim()
    : "";
  if (configuredRequestUrl) {
    try {
      const u = new URL(configuredRequestUrl);
      configuredTarget = `${u.protocol}//${u.host}`;
    } catch {}
  }
  if (!configuredTarget) {
    throw new HttpError(
      503,
      "MISSING_TARGET_HOST_CONFIG",
      "http_requests.outbound_proxy.url must be configured.",
      {
        hint: "Set http_requests.outbound_proxy.url in config to a valid https URL.",
      }
    );
  }
  return configuredTarget;
}

function handleVersion(env) {
  const version = String(env.BUILD_VERSION || "dev");
  const buildTimestamp = String(env.BUILD_TIMESTAMP || env.BUILD_TIME || "");
  return jsonResponse(200, {
    ok: true,
    data: { version, build_timestamp: buildTimestamp || null },
    meta: {},
  });
}

function parseMs(raw) {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

async function handleKeysStatusGet(env) {
  const now = Date.now();
  const [proxyState, issuerState, adminState, config] = await Promise.all([
    getKeyAuthState("proxy", env),
    getKeyAuthState("issuer", env),
    getKeyAuthState("admin", env),
    loadConfigV1(env),
  ]);

  const cleanup = [];
  function normalize(kind, state) {
    let primaryCreatedAt = parseMs(state.primaryCreatedAt);
    let secondaryCreatedAt = parseMs(state.secondaryCreatedAt);
    const oldExpiresAt = parseMs(state.oldExpiresAt);
    const secondaryActive = !!state.old && oldExpiresAt > now;
    if (state.current && !primaryCreatedAt) {
      primaryCreatedAt = now;
      cleanup.push(kvStore(env).put(state.cfg.primaryCreatedAt, String(primaryCreatedAt)));
    }
    if (!state.old) {
      secondaryCreatedAt = 0;
    } else if (!secondaryCreatedAt) {
      secondaryCreatedAt = now;
      cleanup.push(kvStore(env).put(state.cfg.secondaryCreatedAt, String(secondaryCreatedAt)));
    }
    if (state.old && oldExpiresAt <= now) {
      cleanup.push(kvStore(env).delete(state.cfg.old), kvStore(env).delete(state.cfg.oldExpiresAt), kvStore(env).delete(state.cfg.secondaryCreatedAt));
      secondaryCreatedAt = 0;
    }
    const expirySeconds = config?.apiKeyPolicy?.[keyKindConfig(kind).policyKey] ?? null;
    return {
      primary_active: !!state.current,
      secondary_active: secondaryActive,
      [`${kind}_primary_key_created_at`]: primaryCreatedAt || 0,
      [`${kind}_secondary_key_created_at`]: secondaryActive ? secondaryCreatedAt || 0 : 0,
      expiry_seconds: expirySeconds,
    };
  }

  const proxyData = normalize("proxy", proxyState);
  const issuerData = normalize("issuer", issuerState);
  const adminData = normalize("admin", adminState);

  if (cleanup.length > 0) await Promise.all(cleanup);

  return jsonResponse(200, {
    ok: true,
    data: {
      proxy: proxyData,
      issuer: issuerData,
      admin: adminData,
    },
    meta: {},
  });
}

async function handleConfigGet(env) {
  const yamlText = await loadConfigYamlV1(env);
  return new Response(yamlText, {
    status: 200,
    headers: { "content-type": "text/yaml; charset=utf-8" },
  });
}

async function handleConfigPut(request, env) {
  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const parsed = await readConfigInputByContentType(request, maxReq);
  const normalized =
    parsed.format === "yaml"
      ? await saveConfigFromYamlV1(parsed.yamlText, env)
      : await saveConfigObjectV1(parsed.config, env);
  return jsonResponse(200, {
    ok: true,
    data: {
      message: "Configuration updated",
      config: normalized,
    },
    meta: {},
  });
}

async function handleConfigValidate(request, env) {
  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const parsed = await readConfigInputByContentType(request, maxReq);
  const normalized = parsed.config;
  return jsonResponse(200, {
    ok: true,
    data: {
      valid: true,
      config: normalized,
    },
    meta: {},
  });
}

async function readConfigInputByContentType(request, maxBytes) {
  const contentType = getStoredContentType(request.headers);
  if (looksJson(contentType)) {
    const body = await readJsonWithLimit(request, maxBytes);
    if (!isPlainObject(body)) {
      throw new HttpError(400, "INVALID_CONFIG", "Configuration JSON must be an object");
    }
    return { format: "json", config: validateAndNormalizeConfigV1(body) };
  }
  if (looksYaml(contentType)) {
    const yamlText = await readTextWithLimit(request, maxBytes);
    const normalized = await parseYamlConfigText(yamlText);
    return { format: "yaml", config: normalized, yamlText };
  }
  throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json or text/yaml");
}

async function handleConfigTestRule(request, env) {
  enforceInvokeContentType(request);
  const maxReq = getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES);
  const body = await readJsonWithLimit(request, maxReq);

  let config;
  if (typeof body?.config_yaml === "string" && body.config_yaml.trim()) {
    config = await parseYamlConfigText(body.config_yaml);
  } else if (body?.config && isNonArrayObject(body.config)) {
    config = validateAndNormalizeConfigV1(body.config);
  } else {
    config = await loadConfigV1(env);
  }

  const sample = body?.response;
  if (!isNonArrayObject(sample)) {
    throw new HttpError(400, "INVALID_REQUEST", "response object is required", {
      expected: {
        response: {
          status: 404,
          headers: { "content-type": "application/json" },
          body: { error: "Not found" },
          type: "json",
        },
      },
    });
  }

  const status = Number(sample.status);
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    throw new HttpError(400, "INVALID_REQUEST", "response.status must be an integer 100-599");
  }

  const headers = normalizeHeaderMap(sample.headers);
  const contentType = headers["content-type"] || "";
  const type = sample.type ? String(sample.type).toLowerCase() : detectResponseType(contentType);
  if (!VALID_TRANSFORM_TYPES.has(type)) {
    throw new HttpError(400, "INVALID_REQUEST", "response.type must be one of json, text, binary, any");
  }

  const ctx = { status, headers, type };
  const targetResponseSection = config?.transform?.target_response || DEFAULT_CONFIG_V1.transform.target_response;
  const { matchedRule, trace } = selectTransformRule(targetResponseSection, ctx);

  let expression = null;
  let source = "none";
  if (matchedRule) {
    expression = matchedRule.expr;
    source = `rule:${matchedRule.name}`;
  } else if (targetResponseSection.fallback === "transform_default" && targetResponseSection.defaultExpr) {
    expression = targetResponseSection.defaultExpr;
    source = "defaultExpr";
  }

  let output = null;
  if (expression) {
    try {
      output = await evalJsonataWithTimeout(
        expression,
        { status, headers, body: sample.body },
        getEnvInt(env, "TRANSFORM_TIMEOUT_MS", DEFAULTS.TRANSFORM_TIMEOUT_MS)
      );
    } catch (e) {
      throw new HttpError(422, "TRANSFORM_ERROR", "JSONata evaluation failed in test-rule", {
        cause: String(e?.message || e),
      });
    }
  }

  return jsonResponse(200, {
    ok: true,
    data: {
      matched_rule: matchedRule ? matchedRule.name : null,
      expression_source: source,
      fallback_behavior: targetResponseSection.fallback,
      output,
      trace,
    },
    meta: {},
  });
}

async function handleKeyRotationConfigGet(env) {
  const config = await loadConfigV1(env);
  const section = config?.targetCredentialRotation || DEFAULT_CONFIG_V1.targetCredentialRotation;
  return jsonResponse(200, {
    ok: true,
    data: {
      enabled: !!section.enabled,
      strategy: String(section.strategy || "json_ttl"),
      request_yaml: await stringifyYamlConfig(section.request || {}),
      request: section.request || {},
      key_path: String(section?.response?.key_path || ""),
      ttl_path: section?.response?.ttl_path ?? null,
      ttl_unit: String(section?.response?.ttl_unit || "seconds"),
      expires_at_path: section?.response?.expires_at_path ?? null,
      refresh_skew_seconds: Number(section?.trigger?.refresh_skew_seconds ?? 300),
      retry_once_on_401: !!section?.trigger?.retry_once_on_401,
      proxy_expiry_seconds: config?.apiKeyPolicy?.proxyExpirySeconds ?? null,
      issuer_expiry_seconds: config?.apiKeyPolicy?.issuerExpirySeconds ?? null,
      admin_expiry_seconds: config?.apiKeyPolicy?.adminExpirySeconds ?? null,
    },
    meta: {},
  });
}

async function handleKeyRotationConfigPut(request, env) {
  enforceInvokeContentType(request);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const existing = await loadConfigV1(env);

  let requestObj = null;
  if (isNonArrayObject(body?.request)) {
    requestObj = body.request;
  } else {
    const requestYaml = String(body?.request_yaml || "").trim();
    if (!requestYaml) {
      throw new HttpError(400, "INVALID_REQUEST", "request_yaml or request is required", {
        expected: { request_yaml: "method: POST\\nurl: https://..." },
      });
    }
    try {
      const yaml = await loadYamlApi();
      requestObj = yaml.parse(requestYaml);
    } catch (e) {
      throw new HttpError(400, "INVALID_REQUEST", "request_yaml could not be parsed", {
        cause: String(e?.message || e),
      });
    }
    if (!isNonArrayObject(requestObj)) {
      throw new HttpError(400, "INVALID_REQUEST", "request_yaml must parse to an object");
    }
  }

  function toNullableInt(raw, field) {
    if (raw === null || raw === undefined || raw === "") return null;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1) {
      throw new HttpError(400, "INVALID_REQUEST", `${field} must be a positive integer or null`);
    }
    return n;
  }

  const next = {
    ...existing,
    apiKeyPolicy: {
      proxyExpirySeconds: toNullableInt(body?.proxy_expiry_seconds, "proxy_expiry_seconds"),
      issuerExpirySeconds: toNullableInt(body?.issuer_expiry_seconds, "issuer_expiry_seconds"),
      adminExpirySeconds: toNullableInt(body?.admin_expiry_seconds, "admin_expiry_seconds"),
    },
    targetCredentialRotation: {
      enabled: !!body?.enabled,
      strategy: body?.strategy === "oauth_client_credentials" ? "oauth_client_credentials" : "json_ttl",
      request: requestObj,
      response: {
        key_path: String(body?.key_path || ""),
        ttl_path: body?.ttl_path === "" ? null : body?.ttl_path ?? null,
        ttl_unit: String(body?.ttl_unit || "seconds"),
        expires_at_path: body?.expires_at_path === "" ? null : body?.expires_at_path ?? null,
      },
      trigger: {
        refresh_skew_seconds: Number(body?.refresh_skew_seconds ?? 300),
        retry_once_on_401: !!body?.retry_once_on_401,
      },
    },
  };

  const normalized = await saveConfigObjectV1(next, env);
  return jsonResponse(200, {
    ok: true,
    data: {
      message: "Key rotation configuration updated",
      key_rotation: normalized.targetCredentialRotation,
      api_key_policy: normalized.apiKeyPolicy,
    },
    meta: {},
  });
}

function normalizeTransformRuleInput(rule, direction) {
  if (!isNonArrayObject(rule)) return null;
  const out = {
    name: String(rule.name || "").trim(),
    expr: String(rule.expr || ""),
  };
  if (!out.name || !out.expr.trim()) return null;
  if (direction === "target_response") {
    if (Array.isArray(rule.match_status ?? rule.status)) out.match_status = rule.match_status ?? rule.status;
    out.match_type = String(rule.match_type ?? rule.type ?? "any").toLowerCase();
  }
  if (direction === "source_request") {
    if (Array.isArray(rule.match_method ?? rule.method)) {
      out.match_method = (rule.match_method ?? rule.method).map((m) => String(m || "").toUpperCase()).filter(Boolean);
    }
    if (Array.isArray(rule.match_path ?? rule.path)) {
      out.match_path = (rule.match_path ?? rule.path).map((p) => String(p || "")).filter(Boolean);
    }
  }
  if (Array.isArray(rule.match_headers ?? rule.headers)) {
    out.match_headers = (rule.match_headers ?? rule.headers)
      .map((item) => ({ name: String(item?.name || "").toLowerCase(), value: String(item?.value || "") }))
      .filter((item) => item.name && item.value);
  } else if (isNonArrayObject(rule.headerMatch)) {
    out.match_headers = Object.entries(rule.headerMatch)
      .map(([name, value]) => ({ name: String(name || "").toLowerCase(), value: String(value || "") }))
      .filter((item) => item.name && item.value);
  }
  return out;
}

async function handleTransformConfigGet(env) {
  const config = await loadConfigV1(env);
  const transform = config?.transform || DEFAULT_CONFIG_V1.transform;
  return jsonResponse(200, {
    ok: true,
    data: {
      enabled: transform.enabled !== false,
      source_request: transform.source_request || DEFAULT_CONFIG_V1.transform.source_request,
      target_response: transform.target_response || DEFAULT_CONFIG_V1.transform.target_response,
    },
    meta: {},
  });
}

async function handleTransformConfigPut(request, env) {
  enforceInvokeContentType(request);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const existing = await loadConfigV1(env);
  const currentTransform = existing?.transform || DEFAULT_CONFIG_V1.transform;
  const sourceRequestIn = isNonArrayObject(body?.source_request) ? body.source_request : currentTransform.source_request;
  const targetResponseIn = isNonArrayObject(body?.target_response) ? body.target_response : currentTransform.target_response;
  const sourceRequestRules = Array.isArray(sourceRequestIn?.rules)
    ? sourceRequestIn.rules.map((r) => normalizeTransformRuleInput(r, "source_request")).filter((r) => r !== null)
    : [];
  const targetResponseRules = Array.isArray(targetResponseIn?.rules)
    ? targetResponseIn.rules.map((r) => normalizeTransformRuleInput(r, "target_response")).filter((r) => r !== null)
    : [];
  const next = {
    ...existing,
    transform: {
      enabled: body?.enabled === undefined ? currentTransform.enabled !== false : !!body.enabled,
      source_request: {
        enabled: sourceRequestIn?.enabled === undefined ? !!currentTransform?.source_request?.enabled : !!sourceRequestIn.enabled,
        custom_js_preprocessor: sourceRequestIn?.custom_js_preprocessor === undefined
          ? (currentTransform?.source_request?.custom_js_preprocessor ?? null)
          : (sourceRequestIn.custom_js_preprocessor === null ? null : String(sourceRequestIn.custom_js_preprocessor || "").trim() || null),
        defaultExpr: String(sourceRequestIn?.defaultExpr ?? currentTransform?.source_request?.defaultExpr ?? ""),
        fallback: String(sourceRequestIn?.fallback ?? currentTransform?.source_request?.fallback ?? "passthrough"),
        rules: sourceRequestRules,
      },
      target_response: {
        enabled: targetResponseIn?.enabled === undefined ? !!currentTransform?.target_response?.enabled : !!targetResponseIn.enabled,
        custom_js_preprocessor: targetResponseIn?.custom_js_preprocessor === undefined
          ? (currentTransform?.target_response?.custom_js_preprocessor ?? null)
          : (targetResponseIn.custom_js_preprocessor === null ? null : String(targetResponseIn.custom_js_preprocessor || "").trim() || null),
        defaultExpr: String(targetResponseIn?.defaultExpr ?? currentTransform?.target_response?.defaultExpr ?? ""),
        fallback: String(targetResponseIn?.fallback ?? currentTransform?.target_response?.fallback ?? "passthrough"),
        header_filtering: isPlainObject(targetResponseIn?.header_filtering)
          ? targetResponseIn.header_filtering
          : (currentTransform?.target_response?.header_filtering ?? DEFAULT_CONFIG_V1.transform.target_response.header_filtering),
        rules: targetResponseRules,
      },
    },
  };
  const normalized = await saveConfigObjectV1(next, env);
  return jsonResponse(200, {
    ok: true,
    data: {
      message: "Transform configuration updated",
      transform: normalized.transform,
    },
    meta: {},
  });
}

async function isDebugEnabled(env) {
  return observabilityApi.isDebugEnabled(env);
}

function getDebugRedactHeaderSet(config) {
  return observabilityApi.getDebugRedactHeaderSet(config);
}

function toRedactedHeaderMap(headersLike, redactedHeadersSet = null) {
  return observabilityApi.toRedactedHeaderMap(headersLike, redactedHeadersSet);
}

function previewBodyForDebug(value) {
  return observabilityApi.previewBodyForDebug(value);
}

function fmtTs(date = new Date()) {
  return observabilityApi.fmtTs(date);
}

async function handleDebugLastGet(request) {
  return observabilityApi.handleDebugLastGet(request);
}

async function handleLiveLogStream(env) {
  return observabilityApi.handleLiveLogStream(env);
}

async function handleDebugLoggingSecretPut(request, env) {
  enforceInvokeContentType(request);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const value = String(body?.value || "").trim();
  if (!value) {
    throw new HttpError(400, "INVALID_REQUEST", "value is required", {
      expected: { value: "secret-string" },
    });
  }
  const key = authProfileKvKey("logging", "current");
  const issuedKey = authProfileKvKey("logging", "issued_at_ms");
  if (key) {
    await Promise.all([
      kvPutValue(env, key, value),
      issuedKey ? kvStore(env).put(issuedKey, String(Date.now())) : Promise.resolve(),
    ]);
  }
  return jsonResponse(200, {
    ok: true,
    data: {
      logging_secret_set: true,
    },
    meta: {},
  });
}

async function handleDebugLoggingSecretGet(env) {
  const key = authProfileKvKey("logging", "current");
  const secret = key ? await kvGetValue(env, key) : null;
  return jsonResponse(200, {
    ok: true,
    data: {
      logging_secret_set: !!secret,
    },
    meta: {},
  });
}

async function handleDebugLoggingSecretDelete(env) {
  const key = authProfileKvKey("logging", "current");
  const issuedKey = authProfileKvKey("logging", "issued_at_ms");
  const expiresKey = authProfileKvKey("logging", "expires_at_ms");
  const secondaryKey = authProfileKvKey("logging", "secondary");
  const secondaryIssuedKey = authProfileKvKey("logging", "secondary_issued_at_ms");
  const secondaryExpiresKey = authProfileKvKey("logging", "secondary_expires_at_ms");
  const deletes = [
    key,
    issuedKey,
    expiresKey,
    secondaryKey,
    secondaryIssuedKey,
    secondaryExpiresKey,
  ].filter(Boolean).map((k) => kvStore(env).delete(k));
  if (deletes.length) await Promise.all(deletes);
  return jsonResponse(200, {
    ok: true,
    data: {
      logging_secret_set: false,
    },
    meta: {},
  });
}

function parseHttpAuthSecretPath(pathname) {
  const base = `${ADMIN_ROOT}/http-auth/`;
  if (!pathname.startsWith(base)) return null;
  const rest = pathname.slice(base.length);
  const parts = rest.split("/");
  if (parts.length !== 2) return null;
  if (parts[1] !== "secret") return null;
  const profile = decodeURIComponent(parts[0] || "");
  return profile || null;
}

async function handleHttpAuthSecretRoute(pathname, request, env) {
  const profile = parseHttpAuthSecretPath(pathname);
  if (!profile) {
    throw new HttpError(404, "NOT_FOUND", "Route not found");
  }
  if (!authProfilePrefix(profile)) {
    throw new HttpError(400, "INVALID_REQUEST", "Unsupported auth profile");
  }
  if (request.method === "PUT") return await handleHttpAuthSecretPut(profile, request, env);
  if (request.method === "GET") return await handleHttpAuthSecretGet(profile, env);
  if (request.method === "DELETE") return await handleHttpAuthSecretDelete(profile, env);
  throw new HttpError(405, "METHOD_NOT_ALLOWED", "Method not allowed");
}

async function handleHttpAuthSecretPut(profile, request, env) {
  enforceInvokeContentType(request);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const value = String(body?.value || "").trim();
  if (!value) {
    throw new HttpError(400, "INVALID_REQUEST", "value is required", {
      expected: { value: "secret-string" },
    });
  }
  const key = authProfileKvKey(profile, "current");
  const issuedKey = authProfileKvKey(profile, "issued_at_ms");
  if (key) {
    await Promise.all([
      kvPutValue(env, key, value),
      issuedKey ? kvStore(env).put(issuedKey, String(Date.now())) : Promise.resolve(),
    ]);
  }
  return jsonResponse(200, {
    ok: true,
    data: {
      profile,
      secret_set: true,
    },
    meta: {},
  });
}

async function handleHttpAuthSecretGet(profile, env) {
  const key = authProfileKvKey(profile, "current");
  const secret = key ? await kvGetValue(env, key) : null;
  return jsonResponse(200, {
    ok: true,
    data: {
      profile,
      secret_set: !!secret,
    },
    meta: {},
  });
}

async function handleHttpAuthSecretDelete(profile, env) {
  const deletes = AUTH_PROFILE_FIELDS
    .map((field) => authProfileKvKey(profile, field))
    .filter(Boolean)
    .map((key) => kvStore(env).delete(key));
  if (deletes.length) await Promise.all(deletes);
  return jsonResponse(200, {
    ok: true,
    data: {
      profile,
      secret_set: false,
    },
    meta: {},
  });
}

function parseHttpSecretPath(pathname) {
  const base = `${ADMIN_ROOT}/http-secrets/`;
  if (!pathname.startsWith(base)) return null;
  const rest = pathname.slice(base.length);
  if (!rest || rest.includes("/")) return null;
  const ref = decodeURIComponent(rest || "").trim();
  if (!isValidHttpSecretRef(ref)) return null;
  return ref;
}

async function handleHttpSecretRoute(pathname, request, env) {
  const ref = parseHttpSecretPath(pathname);
  if (!ref) {
    throw new HttpError(404, "NOT_FOUND", "Route not found");
  }
  if (request.method === "PUT") return await handleHttpSecretPut(ref, request, env);
  if (request.method === "GET") return await handleHttpSecretGet(ref, env);
  if (request.method === "DELETE") return await handleHttpSecretDelete(ref, env);
  throw new HttpError(405, "METHOD_NOT_ALLOWED", "Method not allowed");
}

async function handleHttpSecretPut(ref, request, env) {
  enforceInvokeContentType(request);
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const value = String(body?.value || "").trim();
  if (!value) {
    throw new HttpError(400, "INVALID_REQUEST", "value is required", {
      expected: { value: "secret-string" },
    });
  }
  const key = httpSecretKvKey(ref);
  if (!key) {
    throw new HttpError(400, "INVALID_REQUEST", "Invalid secret reference");
  }
  await kvPutValue(env, key, value);
  return jsonResponse(200, {
    ok: true,
    data: {
      secret_ref: ref,
      secret_set: true,
    },
    meta: {},
  });
}

async function handleHttpSecretGet(ref, env) {
  const key = httpSecretKvKey(ref);
  const secret = key ? await kvGetValue(env, key) : null;
  return jsonResponse(200, {
    ok: true,
    data: {
      secret_ref: ref,
      secret_set: !!secret,
    },
    meta: {},
  });
}

async function handleHttpSecretDelete(ref, env) {
  const key = httpSecretKvKey(ref);
  if (key) await kvStore(env).delete(key);
  return jsonResponse(200, {
    ok: true,
    data: {
      secret_ref: ref,
      secret_set: false,
    },
    meta: {},
  });
}

async function handleDebugGet(env) {
  return observabilityApi.handleDebugGet(env);
}

async function handleDebugPut(request, env) {
  return observabilityApi.handleDebugPut(request, env);
}

async function handleDebugDelete(env) {
  return observabilityApi.handleDebugDelete(env);
}

async function handleEnrichedHeadersList(env) {
  const names = await listEnrichedHeaderNames(env, getBootstrapEnrichedHeaders(env));
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleEnrichedHeaderPut(request, env, headerNameRaw) {
  enforceInvokeContentType(request);
  const headerName = assertValidHeaderName(headerNameRaw);
  const managedHeaders = getBootstrapEnrichedHeaders(env);
  if (Object.prototype.hasOwnProperty.call(managedHeaders, headerName)) {
    throw new HttpError(409, "HEADER_MANAGED_BY_ENV", "Header is managed by BOOTSTRAP_ENRICHED_HEADERS_JSON and cannot be changed via API.", {
      header: headerName,
      hint: "Update BOOTSTRAP_ENRICHED_HEADERS_JSON and redeploy.",
    });
  }
  const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", DEFAULTS.MAX_REQ_BYTES));
  const value = body?.value;
  if (typeof value !== "string" || !value.length) {
    throw new HttpError(400, "INVALID_REQUEST", "value is required and must be a non-empty string", {
      expected: { value: "string" },
    });
  }

  await kvPutValue(env, enrichedHeaderKvKey(headerName), value);
  const names = await listEnrichedHeaderNames(env, managedHeaders);
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleEnrichedHeaderDelete(env, headerNameRaw) {
  const headerName = assertValidHeaderName(headerNameRaw);
  const managedHeaders = getBootstrapEnrichedHeaders(env);
  if (Object.prototype.hasOwnProperty.call(managedHeaders, headerName)) {
    throw new HttpError(409, "HEADER_MANAGED_BY_ENV", "Header is managed by BOOTSTRAP_ENRICHED_HEADERS_JSON and cannot be deleted via API.", {
      header: headerName,
      hint: "Update BOOTSTRAP_ENRICHED_HEADERS_JSON and redeploy.",
    });
  }
  const kvKey = enrichedHeaderKvKey(headerName);
  const existing = await kvGetValue(env, kvKey);
  if (!existing) {
    throw new HttpError(404, "HEADER_NOT_FOUND", "No enriched header exists for the provided name.", {
      name: headerName,
      hint: `List current enriched headers at ${ADMIN_ROOT}/headers.`,
    });
  }
  await kvStore(env).delete(kvKey);
  const names = await listEnrichedHeaderNames(env, managedHeaders);
  return jsonResponse(200, {
    enriched_headers: names,
  });
}

async function handleRotateByKind(kind, request, env) {
  return keyAuthApi.handleRotateByKind(kind, request, env);
}
