import {
  HttpError,
  isNonArrayObject,
  isPlainObject,
  normalizeHeaderName,
} from "./lib.js";
import { normalizeRequestSecurityConfig, inspectRequestSecurityViolations } from "./outbound_security.js";

const CONFIG_SCHEMA_V1 = {
  proxyName: "string|null",
  http_requests: {
    name: {
      method: "GET|POST|PUT|PATCH|DELETE",
      url: "https URL",
      headers: "{name:value} | [{name,value}]",
      body: "request body object",
      http_authorization: "authorization object",
      security: {
        require_https: "boolean",
        block_private_networks: "boolean",
        method_allowlist: ["GET", "POST"],
        timeout_ms: "integer|null",
        max_response_bytes: "integer|null",
        allowed_hosts: ["api.example.com"],
      },
    },
  },
  http_auth: {
    profiles: {
      name: {
        headers: "mapping<headerName,string>",
        timestamp_format: "epoch_ms|epoch_seconds|iso_8601",
      },
    },
  },
  jwt: {
    enabled: "boolean",
    inbound: {
      enabled: "boolean",
      mode: "shared_secret|jwks",
      header: "string",
      scheme: "string|null",
      issuer: "string|null",
      audience: "string|null",
      http_request: "object|null",
      clock_skew_seconds: "integer>=0",
    },
    outbound: {
      enabled: "boolean",
      header: "string",
      scheme: "string|null",
      issuer: "string|null",
      audience: "string|null",
      subject: "string|null",
      ttl_seconds: "integer>=1|null",
    },
  },
  apiKeyPolicy: {
    proxyExpirySeconds: "integer|null",
    issuerExpirySeconds: "integer|null",
    adminExpirySeconds: "integer|null",
  },
  targetCredentialRotation: {
    enabled: "boolean",
    strategy: "json_ttl|oauth_client_credentials",
    request: "object",
    response: {
      key_path: "string",
      ttl_path: "string|null",
      ttl_unit: "seconds|minutes|hours",
      expires_at_path: "string|null",
    },
    trigger: {
      refresh_skew_seconds: "integer>=0",
      retry_once_on_401: "boolean",
    },
  },
  debug: {
    max_debug_session_seconds: "integer (1-604800)",
    loggingEndpoint: {
      http_request: "object|null",
    },
  },
  transform: {
    enabled: "boolean",
    source_request: {
      enabled: "boolean",
      custom_js_preprocessor: "string|null",
      defaultExpr: "string",
      fallback: "passthrough|error|transform_default",
      rules: [
        {
          name: "string",
          match_method: ["GET", "POST"],
          match_path: ["/v1/*"],
          match_headers: [{ name: "x-example-header", value: "value-or-*contains*" }],
          expr: "string",
        },
      ],
    },
    target_response: {
      enabled: "boolean",
      custom_js_preprocessor: "string|null",
      defaultExpr: "string",
      fallback: "passthrough|error|transform_default",
      header_filtering: {
        mode: "blacklist|whitelist",
        names: ["header-name"],
      },
      rules: [
        {
          name: "string",
          match_status: ["2xx", 422],
          match_type: "json|text|binary|any",
          match_headers: [{ name: "x-example-header", value: "value-or-*contains*" }],
          expr: "string",
        },
      ],
    },
  },
  header_forwarding: {
    mode: "blacklist|whitelist",
    names: ["header-name"],
  },
};

const VALID_FALLBACK_VALUES = new Set(["passthrough", "error", "transform_default"]);
const VALID_TRANSFORM_TYPES = new Set(["json", "text", "binary", "any"]);
const VALID_HEADER_FORWARDING_MODES = new Set(["blacklist", "whitelist"]);
const VALID_JWT_INBOUND_MODES = new Set(["shared_secret", "jwks"]);
const STATUS_CLASS_PATTERN = /^[1-5]xx$/i;
const DEFAULT_HEADER_FORWARDING_NAMES = [
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
  "x-proxy-key",
  "x-admin-key",
  "x-issuer-key",
];

const DEFAULT_CONFIG_V1 = {
  proxyName: null,
  http_requests: {},
  http_auth: {
    profiles: {},
  },
  jwt: {
    enabled: false,
    inbound: {
      enabled: false,
      mode: "shared_secret",
      header: "Authorization",
      scheme: "Bearer",
      issuer: null,
      audience: null,
      http_request: null,
      clock_skew_seconds: 0,
    },
    outbound: {
      enabled: false,
      header: "Authorization",
      scheme: "Bearer",
      issuer: null,
      audience: null,
      subject: null,
      ttl_seconds: 3600,
    },
  },
  apiKeyPolicy: {
    proxyExpirySeconds: null,
    issuerExpirySeconds: null,
    adminExpirySeconds: null,
  },
  targetCredentialRotation: {
    enabled: false,
    strategy: "json_ttl",
    request: {
      method: "POST",
      url: "",
      headers: {},
      body: {
        type: "json",
        value: {},
      },
    },
    response: {
      key_path: "data.apiKey",
      ttl_path: "data.ttl",
      ttl_unit: "seconds",
      expires_at_path: null,
    },
    trigger: {
      refresh_skew_seconds: 300,
      retry_once_on_401: true,
    },
  },
  debug: {
    max_debug_session_seconds: 3600,
    loggingEndpoint: {
      http_request: null,
    },
  },
  transform: {
    enabled: true,
    source_request: {
      enabled: false,
      custom_js_preprocessor: null,
      defaultExpr: "",
      fallback: "passthrough",
      rules: [],
    },
    target_response: {
      enabled: true,
      custom_js_preprocessor: null,
      defaultExpr: "",
      fallback: "passthrough",
      header_filtering: {
        mode: "blacklist",
        names: [],
      },
      rules: [],
    },
  },
  header_forwarding: {
    mode: "blacklist",
    names: [...DEFAULT_HEADER_FORWARDING_NAMES],
  },
};

let yamlApi = null;

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

function pushProblem(problems, path, message) {
  problems.push({ path, message });
}

function ensureNoUnknownKeys(obj, allowedKeys, path, problems) {
  if (!isNonArrayObject(obj)) return;
  for (const key of Object.keys(obj)) {
    if (!allowedKeys.has(key)) {
      pushProblem(problems, `${path}.${key}`, "unknown field");
    }
  }
}

function validateAndNormalizeStatusList(statusList, path, problems) {
  if (!Array.isArray(statusList) || statusList.length === 0) {
    pushProblem(problems, path, "must be a non-empty array");
    return [];
  }

  const normalized = [];
  for (let i = 0; i < statusList.length; i += 1) {
    const value = statusList[i];
    const itemPath = `${path}[${i}]`;
    if (typeof value === "number") {
      if (!Number.isInteger(value) || value < 100 || value > 599) {
        pushProblem(problems, itemPath, "numeric status must be an integer between 100 and 599");
        continue;
      }
      normalized.push(value);
      continue;
    }
    if (typeof value === "string") {
      const s = value.trim();
      if (!STATUS_CLASS_PATTERN.test(s)) {
        pushProblem(problems, itemPath, "string status must be one of 1xx,2xx,3xx,4xx,5xx");
        continue;
      }
      normalized.push(s.toLowerCase());
      continue;
    }
    pushProblem(problems, itemPath, "must be a number or status class string");
  }

  return normalized;
}

function validateAndNormalizeHeaderRules(headers, path, problems) {
  if (headers === undefined) return undefined;
  if (!Array.isArray(headers)) {
    pushProblem(problems, path, "must be an array when provided");
    return undefined;
  }
  const normalized = [];
  for (let i = 0; i < headers.length; i += 1) {
    const item = headers[i];
    const itemPath = `${path}[${i}]`;
    if (!isNonArrayObject(item)) {
      pushProblem(problems, itemPath, "must be an object");
      continue;
    }
    const name = normalizeHeaderName(item.name);
    const value = typeof item.value === "string" ? item.value.trim() : "";
    if (!name) {
      pushProblem(problems, `${itemPath}.name`, "header name must be non-empty");
      continue;
    }
    if (!value) {
      pushProblem(problems, `${itemPath}.value`, "header match value must be a non-empty string");
      continue;
    }
    normalized.push({ name, value });
  }
  return normalized.length ? normalized : undefined;
}

function normalizeLegacyHeaderMatch(headerMatch, path, problems) {
  if (headerMatch === undefined) return undefined;
  if (!isNonArrayObject(headerMatch)) {
    pushProblem(problems, path, "must be an object when provided");
    return undefined;
  }
  const normalized = [];
  for (const [name, value] of Object.entries(headerMatch)) {
    const normalizedName = normalizeHeaderName(name);
    if (!normalizedName) {
      pushProblem(problems, `${path}.${name}`, "header name must be non-empty");
      continue;
    }
    if (typeof value !== "string" || !value.trim()) {
      pushProblem(problems, `${path}.${name}`, "header match value must be a non-empty string");
      continue;
    }
    normalized.push({ name: normalizedName, value: value.trim() });
  }
  return normalized.length ? normalized : undefined;
}

function validateAndNormalizeTransformRule(rule, index, problems, sectionPath, direction) {
  const path = `${sectionPath}.rules[${index}]`;
  if (!isNonArrayObject(rule)) {
    pushProblem(problems, path, "must be an object");
    return null;
  }

  ensureNoUnknownKeys(
    rule,
    new Set([
      "name",
      "status",
      "type",
      "method",
      "path",
      "headers",
      "headerMatch",
      "match_status",
      "match_type",
      "match_method",
      "match_path",
      "match_headers",
      "expr",
    ]),
    path,
    problems
  );

  const name = typeof rule.name === "string" ? rule.name.trim() : "";
  if (!name) pushProblem(problems, `${path}.name`, "must be a non-empty string");

  const statusIn = rule.match_status === undefined ? rule.status : rule.match_status;
  const status = statusIn === undefined ? undefined : validateAndNormalizeStatusList(statusIn, `${path}.match_status`, problems);

  const typeIn = rule.match_type === undefined ? rule.type : rule.match_type;
  const type = typeof typeIn === "string" ? typeIn.trim().toLowerCase() : "";
  if (type && !VALID_TRANSFORM_TYPES.has(type)) {
    pushProblem(problems, `${path}.type`, "must be one of json, text, binary, any");
  }

  const expr = typeof rule.expr === "string" ? rule.expr : "";
  if (!expr.trim()) {
    pushProblem(problems, `${path}.expr`, "must be a non-empty string");
  }

  const headers = validateAndNormalizeHeaderRules(
    rule.match_headers === undefined ? rule.headers : rule.match_headers,
    `${path}.match_headers`,
    problems
  );
  const legacyHeaders = headers ? undefined : normalizeLegacyHeaderMatch(rule.headerMatch, `${path}.headerMatch`, problems);
  const methodIn = rule.match_method === undefined ? rule.method : rule.match_method;
  let method = undefined;
  if (methodIn !== undefined) {
    if (!Array.isArray(methodIn)) {
      pushProblem(problems, `${path}.match_method`, "must be an array of HTTP methods");
    } else {
      method = methodIn
        .map((m, i) => {
          if (typeof m !== "string" || !m.trim()) {
            pushProblem(problems, `${path}.match_method[${i}]`, "must be a non-empty string");
            return "";
          }
          return m.trim().toUpperCase();
        })
        .filter(Boolean);
    }
  }
  const pathIn = rule.match_path === undefined ? rule.path : rule.match_path;
  let rulePath = undefined;
  if (pathIn !== undefined) {
    if (!Array.isArray(pathIn)) {
      pushProblem(problems, `${path}.match_path`, "must be an array of path patterns");
    } else {
      rulePath = pathIn
        .map((p, i) => {
          if (typeof p !== "string" || !p.trim()) {
            pushProblem(problems, `${path}.match_path[${i}]`, "must be a non-empty string");
            return "";
          }
          return p.trim();
        })
        .filter(Boolean);
    }
  }

  const normalized = {
    name,
    expr,
    ...(headers ? { headers } : (legacyHeaders ? { headers: legacyHeaders } : {})),
  };
  if (direction === "target_response") {
    if (status && status.length > 0) normalized.match_status = status;
    normalized.match_type = type || "any";
  }
  if (direction === "source_request") {
    if (method && method.length > 0) normalized.match_method = method;
    if (rulePath && rulePath.length > 0) normalized.match_path = rulePath;
  }
  if (headers || legacyHeaders) {
    normalized.match_headers = headers || legacyHeaders;
    delete normalized.headers;
  }
  return normalized;
}

function isValidHttpSecretRef(ref) {
  return /^[a-zA-Z0-9_.-]{1,64}$/.test(String(ref || ""));
}

function normalizeHttpAuthorizationConfig(input, path, problems) {
  if (input === undefined || input === null) return null;
  if (!isNonArrayObject(input)) {
    pushProblem(problems, path, "must be an object or null");
    return null;
  }
  const typeRaw = input.type === undefined || input.type === null ? "static" : String(input.type || "").trim();
  const type = typeRaw || "static";
  if (!new Set(["static", "key_rotation"]).has(type)) {
    pushProblem(problems, `${path}.type`, "must be static or key_rotation");
  }
  if (type === "static") {
    const staticIn = input.static ?? {};
    if (!isNonArrayObject(staticIn)) {
      pushProblem(problems, `${path}.static`, "must be an object");
      return { type: "static", headers: {}, secret_ref: null };
    }
    const headersIn = staticIn.headers ?? staticIn.auth_headers ?? input.auth_headers ?? {};
    if (!isNonArrayObject(headersIn)) {
      pushProblem(problems, `${path}.static.headers`, "must be an object");
      return { type: "static", headers: {}, secret_ref: null };
    }
    const headers = {};
    for (const [k, v] of Object.entries(headersIn)) {
      const name = String(k || "").trim();
      if (!name) continue;
      headers[name] = String(v ?? "");
    }
    const secretRefRaw = staticIn.secret_ref === undefined || staticIn.secret_ref === null ? null : String(staticIn.secret_ref || "").trim();
    const secret_ref = secretRefRaw || null;
    if (secret_ref && !isValidHttpSecretRef(secret_ref)) {
      pushProblem(problems, `${path}.static.secret_ref`, "must match [a-zA-Z0-9_.-] and be <= 64 chars");
    }
    return { type: "static", headers, secret_ref };
  }
  const rotationIn = input.key_rotation ?? {};
  const defaultScope = path.startsWith("$.jwt")
    ? "jwt"
    : (path.startsWith("$.debug") ? "logging" : (path.includes("targetCredentialRotation") ? "target" : null));
  if (!isNonArrayObject(rotationIn)) {
    pushProblem(problems, `${path}.key_rotation`, "must be an object");
    return { type: "key_rotation", profile: null, auth_headers: {}, key_rotation_http_request: null, key_rotation_http_response: {} };
  }
  const profileRaw = rotationIn.profile === undefined || rotationIn.profile === null ? "" : String(rotationIn.profile || "").trim();
  const authHeadersIn = input.auth_headers ?? rotationIn.auth_headers ?? {};
  const auth_headers = {};
  if (Array.isArray(authHeadersIn)) {
    authHeadersIn.forEach((entry, idx) => {
      if (!isNonArrayObject(entry)) {
        pushProblem(problems, `${path}.auth_headers[${idx}]`, "must be an object with name/value");
        return;
      }
      const name = String(entry.name || "").trim();
      if (!name) {
        pushProblem(problems, `${path}.auth_headers[${idx}].name`, "must be a non-empty string");
        return;
      }
      auth_headers[name] = String(entry.value ?? "");
    });
  } else if (isNonArrayObject(authHeadersIn)) {
    for (const [k, v] of Object.entries(authHeadersIn)) {
      const name = String(k || "").trim();
      if (!name) continue;
      auth_headers[name] = String(v ?? "");
    }
  } else if (input.auth_headers !== undefined || rotationIn.auth_headers !== undefined) {
    pushProblem(problems, `${path}.auth_headers`, "must be an object or array of {name,value}");
  }
  const key_rotation_http_request = normalizeHttpRequestConfig(
    isNonArrayObject(rotationIn.key_rotation_http_request)
      ? { ...rotationIn.key_rotation_http_request, __kv_scope: rotationIn.key_rotation_http_request.__kv_scope || defaultScope }
      : (rotationIn.key_rotation_http_request ?? null),
    `${path}.key_rotation.key_rotation_http_request`,
    problems,
    false
  );
  const keyRotationHttpResponseIn = rotationIn.key_rotation_http_response ?? {};
  const key_rotation_http_response = {};
  if (isNonArrayObject(keyRotationHttpResponseIn)) {
    for (const [k, v] of Object.entries(keyRotationHttpResponseIn)) {
      const name = String(k || "").trim();
      if (!name) continue;
      key_rotation_http_response[name] = String(v ?? "");
    }
  } else if (rotationIn.key_rotation_http_response !== undefined) {
    pushProblem(problems, `${path}.key_rotation.key_rotation_http_response`, "must be an object");
  }
  // master.yaml shape alias:
  // key_rotation:
  //   store_auth_key_from: data.apiKey
  //   store_key_ttl_from: data.ttl
  //   ttl_unit: epoch_seconds
  if (!Object.keys(key_rotation_http_response).length) {
    const storeAuthKeyFrom = String(rotationIn.store_auth_key_from || "").trim();
    const storeKeyTtlFrom = String(rotationIn.store_key_ttl_from || "").trim();
    const ttlUnit = String(rotationIn.ttl_unit || "").trim();
    if (storeAuthKeyFrom) key_rotation_http_response.current_token_value = storeAuthKeyFrom;
    if (storeKeyTtlFrom) key_rotation_http_response.current_token_ttl = storeKeyTtlFrom;
    if (ttlUnit) key_rotation_http_response.current_token_ttl_unit = ttlUnit;
  }
  if (!profileRaw && !key_rotation_http_request && Object.keys(key_rotation_http_response).length === 0) {
    pushProblem(problems, `${path}.key_rotation`, "must define profile or key_rotation_http_request/key_rotation_http_response");
  }
  return {
    type: "key_rotation",
    profile: profileRaw || null,
    auth_headers,
    key_rotation_http_request,
    key_rotation_http_response,
  };
}

function normalizeHttpRequestConfig(input, path, problems, requireUrl) {
  if (input === undefined || input === null) return null;
  if (!isNonArrayObject(input)) {
    pushProblem(problems, path, "must be an object or null");
    return null;
  }
  const methodRaw = input.method === undefined || input.method === null ? "GET" : String(input.method || "").trim();
  const method = methodRaw ? methodRaw.toUpperCase() : "GET";
  const urlRaw = input.url === undefined || input.url === null ? "" : String(input.url || "").trim();
  if (requireUrl && !urlRaw) {
    pushProblem(problems, path + ".url", "must be provided");
  }
  if (urlRaw) {
    try {
      const u = new URL(urlRaw);
      if (u.protocol !== "https:") {
        pushProblem(problems, path + ".url", "must use https");
      }
    } catch {
      pushProblem(problems, path + ".url", "must be a valid URL");
    }
  }
  let headers = {};
  if (input.headers !== undefined && input.headers !== null) {
    if (Array.isArray(input.headers)) {
      headers = {};
      input.headers.forEach((entry, idx) => {
        if (!isNonArrayObject(entry)) {
          pushProblem(problems, `${path}.headers[${idx}]`, "must be an object with name/value");
          return;
        }
        const name = String(entry.name || "").trim();
        if (!name) {
          pushProblem(problems, `${path}.headers[${idx}].name`, "must be a non-empty string");
          return;
        }
        headers[name] = String(entry.value ?? "");
      });
    } else if (!isNonArrayObject(input.headers)) {
      pushProblem(problems, path + ".headers", "must be an object or an array of {name,value}");
    } else {
      headers = {};
      for (const [k, v] of Object.entries(input.headers)) {
        const name = String(k || "").trim();
        if (!name) continue;
        headers[name] = String(v ?? "");
      }
    }
  }
  let body = input.body !== undefined ? input.body : null;
  const bodyTypeAlias = input.body_type === undefined || input.body_type === null ? "" : String(input.body_type || "").trim().toLowerCase();
  if (bodyTypeAlias) {
    if (bodyTypeAlias === "none") {
      body = { type: "none" };
    } else if (bodyTypeAlias === "json") {
      body = { type: "json", value: isNonArrayObject(input.body) || Array.isArray(input.body) ? input.body : (input.body ?? {}) };
    } else if (bodyTypeAlias === "urlencoded") {
      body = { type: "urlencoded", value: isNonArrayObject(input.body) ? input.body : {} };
    } else if (bodyTypeAlias === "raw") {
      body = { type: "raw", raw: typeof input.body === "string" ? input.body : String(input.body ?? "") };
    }
  }
  const authProfileRaw = input.auth_profile === undefined || input.auth_profile === null ? null : String(input.auth_profile || "").trim();
  const legacyProfile = authProfileRaw || null;
  const authInput = input.http_authorization !== undefined ? input.http_authorization : input.authorization;
  let http_authorization = normalizeHttpAuthorizationConfig(authInput, path + ".http_authorization", problems);
  if (!http_authorization && legacyProfile) {
    http_authorization = { type: "key_rotation", profile: legacyProfile };
  }
  return {
    method,
    url: urlRaw || null,
    headers,
    body,
    http_authorization,
    auth_profile: legacyProfile || null,
    __kv_scope: typeof input.__kv_scope === "string" ? String(input.__kv_scope).trim() : null,
    security: (() => {
      const normalized = normalizeRequestSecurityConfig(input.security, `${path}.security`);
      for (const problem of normalized.problems || []) {
        pushProblem(problems, problem.path, problem.message);
      }
      return normalized.value;
    })(),
  };
}

function authProfilePrefix(name) {
  const key = String(name || "").trim();
  const supported = new Set(["logging", "target", "jwt_inbound"]);
  return supported.has(key) ? key : null;
}

function validateAndNormalizeConfigV1(configInput) {
  const problems = [];
  const inputRaw = configInput ?? {};

  if (!isNonArrayObject(inputRaw)) {
    throw new HttpError(400, "INVALID_CONFIG", "Configuration must be an object", {
      expected: CONFIG_SCHEMA_V1,
      received_type: typeof configInput,
    });
  }
  const input = { ...inputRaw };
  let jwtModeAlias = null;
  // master.yaml aliases -> runtime internal keys
  if (input.proxyName === undefined && input.proxy_friendly_name !== undefined) {
    input.proxyName = input.proxy_friendly_name;
  }
  if (input.apiKeyPolicy === undefined && isNonArrayObject(input.proxy_access_control)) {
    const pac = input.proxy_access_control;
    input.apiKeyPolicy = {
      proxyExpirySeconds: pac?.proxy_key?.expiry_in_seconds ?? null,
      issuerExpirySeconds: pac?.jwt_issuer_key?.expiry_in_seconds ?? null,
      adminExpirySeconds: pac?.admin_key?.expiry_in_seconds ?? null,
    };
  }
  if (isNonArrayObject(input.logging)) {
    const max = input.logging.max_logging_session_seconds;
    input.debug = {
      ...(isNonArrayObject(input.debug) ? input.debug : {}),
      ...(max !== undefined ? { max_debug_session_seconds: max } : {}),
    };
  }
  if (
    isNonArrayObject(input.jwt) &&
    (Object.prototype.hasOwnProperty.call(input.jwt, "mode") ||
      Object.prototype.hasOwnProperty.call(input.jwt, "verify_external_tokens") ||
      Object.prototype.hasOwnProperty.call(input.jwt, "issue_tokens"))
  ) {
    const jwtInRaw = input.jwt;
    const mode = String(jwtInRaw.mode || "").trim();
    jwtModeAlias = mode;
    const verifyCfg = isNonArrayObject(jwtInRaw.verify_external_tokens) ? jwtInRaw.verify_external_tokens : {};
    const issueCfg = isNonArrayObject(jwtInRaw.issue_tokens) ? jwtInRaw.issue_tokens : {};
    const verifyEnabled = mode === "verify_external_tokens";
    const issueEnabled = mode === "issue_tokens";
    const inboundLegacy = isNonArrayObject(jwtInRaw.inbound) ? jwtInRaw.inbound : {};
    const outboundLegacy = isNonArrayObject(jwtInRaw.outbound) ? jwtInRaw.outbound : {};
    input.jwt = {
      enabled: verifyEnabled || issueEnabled,
      inbound: {
        ...inboundLegacy,
        enabled: verifyEnabled,
        clock_skew_seconds: verifyCfg.clock_skew_seconds ?? inboundLegacy.clock_skew_seconds,
        http_request: verifyCfg.http_request ?? inboundLegacy.http_request ?? null,
      },
      outbound: {
        ...outboundLegacy,
        enabled: issueEnabled,
        header: issueCfg.header ?? outboundLegacy.header,
        scheme: issueCfg.scheme ?? outboundLegacy.scheme,
        issuer: issueCfg.issuer ?? outboundLegacy.issuer,
        audience: issueCfg.audience ?? outboundLegacy.audience,
        subject: issueCfg.subject ?? outboundLegacy.subject,
        ttl_seconds: issueCfg.ttl_seconds ?? outboundLegacy.ttl_seconds,
      },
    };
  }

  if (input.targetHost !== undefined || input.target_host !== undefined) {
    pushProblem(
      problems,
      "$.target_host",
      "is not supported; configure host via http_requests.outbound_proxy.url"
    );
  }

  const proxyNameRaw = input.proxyName;
  let proxyName = null;
  if (proxyNameRaw !== undefined && proxyNameRaw !== null && proxyNameRaw !== "") {
    if (typeof proxyNameRaw !== "string") {
      pushProblem(problems, "$.proxyName", "must be a string or null");
    } else {
      proxyName = proxyNameRaw.trim() || null;
    }
  }

  const httpRequestsIn = input.http_requests ?? {};
  const http_requests = {};
  if (httpRequestsIn !== undefined && !isNonArrayObject(httpRequestsIn)) {
    pushProblem(problems, "$.http_requests", "must be an object when provided");
  } else if (isNonArrayObject(httpRequestsIn)) {
    for (const [reqNameRaw, reqValue] of Object.entries(httpRequestsIn)) {
      const reqName = String(reqNameRaw || "").trim();
      if (!reqName) {
        pushProblem(problems, "$.http_requests", "request names must be non-empty");
        continue;
      }
      const normalizedReq = normalizeHttpRequestConfig(reqValue, `$.http_requests.${reqName}`, problems, false);
      if (normalizedReq) http_requests[reqName] = normalizedReq;
    }
  }
  for (const [reqName, reqModel] of Object.entries(http_requests)) {
    const requestPath = `$.http_requests.${reqName}`;
    const violations = inspectRequestSecurityViolations(requestPath, reqModel);
    for (const violation of violations) {
      pushProblem(problems, violation.path, violation.message);
    }
  }
  // Link sibling key rotation request models by convention:
  // <request_name> + "_key_rotation"
  for (const [reqName, reqModel] of Object.entries(http_requests)) {
    if (!isNonArrayObject(reqModel)) continue;
    const auth = isNonArrayObject(reqModel.http_authorization) ? reqModel.http_authorization : null;
    if (!auth || auth.type !== "key_rotation") continue;
    if (!auth.key_rotation_http_request) {
      const rotateReq = http_requests[`${reqName}_key_rotation`];
      if (isNonArrayObject(rotateReq)) {
        auth.key_rotation_http_request = rotateReq;
      }
    }
  }
  if (
    jwtModeAlias === "verify_external_tokens" &&
    isNonArrayObject(input.jwt) &&
    isNonArrayObject(input.jwt.inbound) &&
    !input.jwt.inbound.http_request &&
    isNonArrayObject(http_requests.jwt_fetch)
  ) {
    input.jwt.inbound.http_request = http_requests.jwt_fetch;
  }
  const httpAuthIn = input.http_auth ?? {};
  if (!isNonArrayObject(httpAuthIn)) {
    pushProblem(problems, "$.http_auth", "must be an object when provided");
  }
  if (isNonArrayObject(httpAuthIn)) {
    ensureNoUnknownKeys(httpAuthIn, new Set(["profiles"]), "$.http_auth", problems);
  }
  const profilesIn = isNonArrayObject(httpAuthIn) ? (httpAuthIn.profiles ?? {}) : {};
  if (!isNonArrayObject(profilesIn)) {
    pushProblem(problems, "$.http_auth.profiles", "must be an object when provided");
  }
  const httpAuthProfiles = {};
  if (isNonArrayObject(profilesIn)) {
    for (const [name, value] of Object.entries(profilesIn)) {
      const n = String(name || "").trim();
      if (!n) {
        pushProblem(problems, "$.http_auth.profiles", "profile names must be non-empty strings");
        continue;
      }
      if (!authProfilePrefix(n)) {
        pushProblem(problems, `$.http_auth.profiles.${name}`, "profile name is not supported");
        continue;
      }
      if (!isNonArrayObject(value)) {
        pushProblem(problems, `$.http_auth.profiles.${name}`, "must be an object");
        continue;
      }
      ensureNoUnknownKeys(value, new Set(["headers", "timestamp_format"]), `$.http_auth.profiles.${name}`, problems);
      const headersIn = value.headers ?? {};
      if (!isNonArrayObject(headersIn)) {
        pushProblem(problems, `$.http_auth.profiles.${name}.headers`, "must be an object");
      }
      const headers = {};
      if (isNonArrayObject(headersIn)) {
        for (const [k, v] of Object.entries(headersIn)) {
          const key = String(k || "").trim();
          if (!key) continue;
          headers[key] = String(v ?? "");
        }
      }
      const ts = value.timestamp_format === undefined || value.timestamp_format === null ? "epoch_ms" : String(value.timestamp_format || "").trim();
      if (!new Set(["epoch_ms", "epoch_seconds", "iso_8601"]).has(ts)) {
        pushProblem(problems, `$.http_auth.profiles.${name}.timestamp_format`, "must be epoch_ms, epoch_seconds, or iso_8601");
      }
      httpAuthProfiles[n] = {
        headers,
        timestamp_format: new Set(["epoch_ms", "epoch_seconds", "iso_8601"]).has(ts) ? ts : "epoch_ms",
      };
    }
  }

  const jwtIn = input.jwt ?? {};
  if (!isNonArrayObject(jwtIn)) {
    pushProblem(problems, "$.jwt", "must be an object when provided");
  }
  if (isNonArrayObject(jwtIn)) {
    ensureNoUnknownKeys(jwtIn, new Set(["enabled", "inbound", "outbound"]), "$.jwt", problems);
  }

  const jwtEnabled = isNonArrayObject(jwtIn) && jwtIn.enabled !== undefined ? jwtIn.enabled : false;
  if (typeof jwtEnabled !== "boolean") {
    pushProblem(problems, "$.jwt.enabled", "must be a boolean");
  }

  const jwtInboundIn = isNonArrayObject(jwtIn) ? (jwtIn.inbound ?? {}) : {};
  if (!isNonArrayObject(jwtInboundIn)) {
    pushProblem(problems, "$.jwt.inbound", "must be an object when provided");
  }
  if (isNonArrayObject(jwtInboundIn)) {
    ensureNoUnknownKeys(
      jwtInboundIn,
      new Set(["enabled", "mode", "header", "scheme", "issuer", "audience", "http_request", "clock_skew_seconds"]),
      "$.jwt.inbound",
      problems
    );
  }

  const jwtInboundEnabled = isNonArrayObject(jwtInboundIn) && jwtInboundIn.enabled !== undefined ? jwtInboundIn.enabled : false;
  if (typeof jwtInboundEnabled !== "boolean") {
    pushProblem(problems, "$.jwt.inbound.enabled", "must be a boolean");
  }
  const jwtInboundMode = isNonArrayObject(jwtInboundIn) && jwtInboundIn.mode !== undefined ? String(jwtInboundIn.mode) : "shared_secret";
  if (!VALID_JWT_INBOUND_MODES.has(jwtInboundMode)) {
    pushProblem(problems, "$.jwt.inbound.mode", "must be shared_secret or jwks");
  }
  const jwtInboundHeader = isNonArrayObject(jwtInboundIn) && jwtInboundIn.header !== undefined ? normalizeHeaderName(jwtInboundIn.header) : "authorization";
  if (!jwtInboundHeader) {
    pushProblem(problems, "$.jwt.inbound.header", "must be a non-empty header name");
  }
  const jwtInboundScheme = isNonArrayObject(jwtInboundIn) && jwtInboundIn.scheme !== undefined && jwtInboundIn.scheme !== null
    ? String(jwtInboundIn.scheme || "").trim()
    : "Bearer";
  const jwtInboundIssuer = isNonArrayObject(jwtInboundIn) && jwtInboundIn.issuer !== undefined && jwtInboundIn.issuer !== null ? String(jwtInboundIn.issuer || "").trim() : null;
  const jwtInboundAudience = isNonArrayObject(jwtInboundIn) && jwtInboundIn.audience !== undefined && jwtInboundIn.audience !== null ? String(jwtInboundIn.audience || "").trim() : null;
  let jwtInboundHttpRequest = normalizeHttpRequestConfig(
    isNonArrayObject(jwtInboundIn) && isNonArrayObject(jwtInboundIn.http_request)
      ? { ...jwtInboundIn.http_request, __kv_scope: "jwt" }
      : (isNonArrayObject(jwtInboundIn) ? jwtInboundIn.http_request : null),
    "$.jwt.inbound.http_request",
    problems,
    false
  );
  const jwtInboundSkew = isNonArrayObject(jwtInboundIn) && jwtInboundIn.clock_skew_seconds !== undefined ? Number(jwtInboundIn.clock_skew_seconds) : 0;
  if (!Number.isInteger(jwtInboundSkew) || jwtInboundSkew < 0) {
    pushProblem(problems, "$.jwt.inbound.clock_skew_seconds", "must be an integer >= 0");
  }

  const jwtOutboundIn = isNonArrayObject(jwtIn) ? (jwtIn.outbound ?? {}) : {};
  if (!isNonArrayObject(jwtOutboundIn)) {
    pushProblem(problems, "$.jwt.outbound", "must be an object when provided");
  }
  if (isNonArrayObject(jwtOutboundIn)) {
    ensureNoUnknownKeys(jwtOutboundIn, new Set(["enabled", "header", "scheme", "issuer", "audience", "subject", "ttl_seconds"]), "$.jwt.outbound", problems);
  }

  const jwtOutboundEnabled = isNonArrayObject(jwtOutboundIn) && jwtOutboundIn.enabled !== undefined ? jwtOutboundIn.enabled : false;
  if (typeof jwtOutboundEnabled !== "boolean") {
    pushProblem(problems, "$.jwt.outbound.enabled", "must be a boolean");
  }
  const jwtOutboundHeader = isNonArrayObject(jwtOutboundIn) && jwtOutboundIn.header !== undefined ? normalizeHeaderName(jwtOutboundIn.header) : "authorization";
  if (!jwtOutboundHeader) {
    pushProblem(problems, "$.jwt.outbound.header", "must be a non-empty header name");
  }
  const jwtOutboundScheme = isNonArrayObject(jwtOutboundIn) && jwtOutboundIn.scheme !== undefined && jwtOutboundIn.scheme !== null
    ? String(jwtOutboundIn.scheme || "").trim()
    : "Bearer";
  const jwtOutboundIssuer = isNonArrayObject(jwtOutboundIn) && jwtOutboundIn.issuer !== undefined && jwtOutboundIn.issuer !== null ? String(jwtOutboundIn.issuer || "").trim() : null;
  const jwtOutboundAudience = isNonArrayObject(jwtOutboundIn) && jwtOutboundIn.audience !== undefined && jwtOutboundIn.audience !== null ? String(jwtOutboundIn.audience || "").trim() : null;
  const jwtOutboundSubject = isNonArrayObject(jwtOutboundIn) && jwtOutboundIn.subject !== undefined && jwtOutboundIn.subject !== null ? String(jwtOutboundIn.subject || "").trim() : null;
  const jwtOutboundTtlRaw = isNonArrayObject(jwtOutboundIn) ? jwtOutboundIn.ttl_seconds : undefined;
  const jwtOutboundTtl = jwtOutboundTtlRaw === undefined || jwtOutboundTtlRaw === null ? 3600 : Number(jwtOutboundTtlRaw);
  if (!Number.isInteger(jwtOutboundTtl) || jwtOutboundTtl < 1) {
    pushProblem(problems, "$.jwt.outbound.ttl_seconds", "must be a positive integer or null");
  }

  const apiKeyPolicyIn = input.apiKeyPolicy ?? {};
  if (!isNonArrayObject(apiKeyPolicyIn)) {
    pushProblem(problems, "$.apiKeyPolicy", "must be an object when provided");
  }
  if (isNonArrayObject(apiKeyPolicyIn)) {
    ensureNoUnknownKeys(apiKeyPolicyIn, new Set(["proxyExpirySeconds", "issuerExpirySeconds", "adminExpirySeconds"]), "$.apiKeyPolicy", problems);
  }

  function readExpirySeconds(raw, path) {
    if (raw === undefined || raw === null) return null;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1) {
      pushProblem(problems, path, "must be a positive integer or null");
      return null;
    }
    return n;
  }

  const proxyExpirySeconds = readExpirySeconds(isNonArrayObject(apiKeyPolicyIn) ? apiKeyPolicyIn.proxyExpirySeconds : undefined, "$.apiKeyPolicy.proxyExpirySeconds");
  const issuerExpirySeconds = readExpirySeconds(isNonArrayObject(apiKeyPolicyIn) ? apiKeyPolicyIn.issuerExpirySeconds : undefined, "$.apiKeyPolicy.issuerExpirySeconds");
  const adminExpirySeconds = readExpirySeconds(isNonArrayObject(apiKeyPolicyIn) ? apiKeyPolicyIn.adminExpirySeconds : undefined, "$.apiKeyPolicy.adminExpirySeconds");

  const tcrIn = input.targetCredentialRotation ?? {};
  if (!isNonArrayObject(tcrIn)) {
    pushProblem(problems, "$.targetCredentialRotation", "must be an object when provided");
  }
  if (isNonArrayObject(tcrIn)) {
    ensureNoUnknownKeys(tcrIn, new Set(["enabled", "strategy", "request", "response", "trigger"]), "$.targetCredentialRotation", problems);
  }
  const tcrEnabled = isNonArrayObject(tcrIn) && tcrIn.enabled !== undefined ? tcrIn.enabled : false;
  if (typeof tcrEnabled !== "boolean") pushProblem(problems, "$.targetCredentialRotation.enabled", "must be a boolean");
  const tcrStrategy = isNonArrayObject(tcrIn) && tcrIn.strategy !== undefined ? String(tcrIn.strategy) : "json_ttl";
  if (!new Set(["json_ttl", "oauth_client_credentials"]).has(tcrStrategy)) {
    pushProblem(problems, "$.targetCredentialRotation.strategy", "must be json_ttl or oauth_client_credentials");
  }
  const tcrRequestRaw = isNonArrayObject(tcrIn) && tcrIn.request !== undefined ? tcrIn.request : DEFAULT_CONFIG_V1.targetCredentialRotation.request;
  if (!isNonArrayObject(tcrRequestRaw)) pushProblem(problems, "$.targetCredentialRotation.request", "must be an object");
  const tcrResponseIn = isNonArrayObject(tcrIn) && tcrIn.response !== undefined ? tcrIn.response : {};
  if (!isNonArrayObject(tcrResponseIn)) pushProblem(problems, "$.targetCredentialRotation.response", "must be an object");
  const tcrKeyPath = isNonArrayObject(tcrResponseIn) && tcrResponseIn.key_path !== undefined ? String(tcrResponseIn.key_path || "") : "data.apiKey";
  if (!tcrKeyPath.trim()) pushProblem(problems, "$.targetCredentialRotation.response.key_path", "must be a non-empty string");
  const tcrTtlPathRaw = isNonArrayObject(tcrResponseIn) ? tcrResponseIn.ttl_path : undefined;
  const tcrTtlPath = tcrTtlPathRaw === undefined || tcrTtlPathRaw === null ? null : String(tcrTtlPathRaw || "").trim();
  const tcrExpiresAtPathRaw = isNonArrayObject(tcrResponseIn) ? tcrResponseIn.expires_at_path : undefined;
  const tcrExpiresAtPath = tcrExpiresAtPathRaw === undefined || tcrExpiresAtPathRaw === null ? null : String(tcrExpiresAtPathRaw || "").trim();
  if (!tcrTtlPath && !tcrExpiresAtPath) {
    pushProblem(problems, "$.targetCredentialRotation.response", "must define ttl_path or expires_at_path");
  }
  const tcrTtlUnit = isNonArrayObject(tcrResponseIn) && tcrResponseIn.ttl_unit !== undefined ? String(tcrResponseIn.ttl_unit) : "seconds";
  if (!new Set(["seconds", "minutes", "hours"]).has(tcrTtlUnit)) {
    pushProblem(problems, "$.targetCredentialRotation.response.ttl_unit", "must be seconds, minutes, or hours");
  }
  const tcrTriggerIn = isNonArrayObject(tcrIn) && tcrIn.trigger !== undefined ? tcrIn.trigger : {};
  if (!isNonArrayObject(tcrTriggerIn)) pushProblem(problems, "$.targetCredentialRotation.trigger", "must be an object");
  const tcrSkew = isNonArrayObject(tcrTriggerIn) && tcrTriggerIn.refresh_skew_seconds !== undefined ? Number(tcrTriggerIn.refresh_skew_seconds) : 300;
  if (!Number.isInteger(tcrSkew) || tcrSkew < 0) pushProblem(problems, "$.targetCredentialRotation.trigger.refresh_skew_seconds", "must be an integer >= 0");
  const tcrRetry = isNonArrayObject(tcrTriggerIn) && tcrTriggerIn.retry_once_on_401 !== undefined ? tcrTriggerIn.retry_once_on_401 : true;
  if (typeof tcrRetry !== "boolean") pushProblem(problems, "$.targetCredentialRotation.trigger.retry_once_on_401", "must be a boolean");

  const transformIn = input.transform ?? {};
  if (!isNonArrayObject(transformIn)) {
    pushProblem(problems, "$.transform", "must be an object when provided");
  }
  if (isNonArrayObject(transformIn)) {
    ensureNoUnknownKeys(transformIn, new Set(["enabled", "source_request", "target_response"]), "$.transform", problems);
  }

  const enabled = transformIn.enabled === undefined ? true : transformIn.enabled;
  if (typeof enabled !== "boolean") {
    pushProblem(problems, "$.transform.enabled", "must be a boolean");
  }

  function normalizeTransformSection(sectionIn, path, direction, legacy) {
    const src = sectionIn === undefined ? legacy : sectionIn;
    if (!isNonArrayObject(src)) {
      pushProblem(problems, path, "must be an object");
      return { enabled: direction === "target_response", defaultExpr: "", fallback: "passthrough", rules: [] };
    }
    ensureNoUnknownKeys(src, new Set(["enabled", "defaultExpr", "fallback", "rules", "header_filtering", "custom_js_preprocessor"]), path, problems);
    const sectionEnabled = src.enabled === undefined ? (direction === "target_response") : src.enabled;
    if (typeof sectionEnabled !== "boolean") {
      pushProblem(problems, `${path}.enabled`, "must be a boolean");
    }
    const sectionDefaultExpr = src.defaultExpr === undefined ? "" : src.defaultExpr;
    if (typeof sectionDefaultExpr !== "string") {
      pushProblem(problems, `${path}.defaultExpr`, "must be a string");
    }
    const sectionFallback = src.fallback === undefined ? "passthrough" : String(src.fallback);
    if (!VALID_FALLBACK_VALUES.has(sectionFallback)) {
      pushProblem(problems, `${path}.fallback`, "must be passthrough, error, or transform_default");
    }
    const sectionRulesIn = src.rules === undefined ? [] : src.rules;
    if (!Array.isArray(sectionRulesIn)) {
      pushProblem(problems, `${path}.rules`, "must be an array");
    }
    const sectionRules = Array.isArray(sectionRulesIn)
      ? sectionRulesIn
          .map((rule, index) => validateAndNormalizeTransformRule(rule, index, problems, path, direction))
          .filter((rule) => rule !== null)
      : [];
    let headerFiltering = DEFAULT_CONFIG_V1.transform.target_response.header_filtering;
    if (isNonArrayObject(src.header_filtering)) {
      const hf = src.header_filtering;
      ensureNoUnknownKeys(hf, new Set(["mode", "names"]), `${path}.header_filtering`, problems);
      const mode = hf.mode === "whitelist" ? "whitelist" : "blacklist";
      const names = Array.isArray(hf.names)
        ? hf.names.map((n) => normalizeHeaderName(n)).filter(Boolean)
        : [];
      headerFiltering = { mode, names };
    }
    return {
      enabled: !!sectionEnabled,
      custom_js_preprocessor: src.custom_js_preprocessor === undefined || src.custom_js_preprocessor === null
        ? null
        : String(src.custom_js_preprocessor || "").trim() || null,
      defaultExpr: typeof sectionDefaultExpr === "string" ? sectionDefaultExpr : "",
      fallback: VALID_FALLBACK_VALUES.has(sectionFallback) ? sectionFallback : "passthrough",
      header_filtering: headerFiltering,
      rules: sectionRules,
    };
  }

  const sourceRequestSection = normalizeTransformSection(
    transformIn.source_request,
    "$.transform.source_request",
    "source_request",
    DEFAULT_CONFIG_V1.transform.source_request
  );
  const targetResponseSection = normalizeTransformSection(
    transformIn.target_response,
    "$.transform.target_response",
    "target_response",
    DEFAULT_CONFIG_V1.transform.target_response
  );

  const debugIn = input.debug ?? {};
  if (!isNonArrayObject(debugIn)) {
    pushProblem(problems, "$.debug", "must be an object when provided");
  }
  if (isNonArrayObject(debugIn)) {
    ensureNoUnknownKeys(debugIn, new Set(["max_debug_session_seconds", "loggingEndpoint"]), "$.debug", problems);
  }
  const maxTtlSecondsRaw = isNonArrayObject(debugIn) ? debugIn.max_debug_session_seconds : undefined;
  const maxTtlSeconds = maxTtlSecondsRaw === undefined ? 3600 : Number(maxTtlSecondsRaw);
  if (!Number.isInteger(maxTtlSeconds)) {
    pushProblem(problems, "$.debug.max_debug_session_seconds", "must be an integer");
  } else if (maxTtlSeconds < 1 || maxTtlSeconds > 604800) {
    pushProblem(problems, "$.debug.max_debug_session_seconds", "must be between 1 and 604800 (7 days)");
  }
  const loggingUrlIn = isNonArrayObject(debugIn) && debugIn.loggingEndpoint !== undefined ? debugIn.loggingEndpoint : {};
  if (!isNonArrayObject(loggingUrlIn)) {
    pushProblem(problems, "$.debug.loggingEndpoint", "must be an object when provided");
  }
  if (isNonArrayObject(loggingUrlIn)) {
    ensureNoUnknownKeys(loggingUrlIn, new Set(["http_request"]), "$.debug.loggingEndpoint", problems);
  }
  const sinkHttpRequest = normalizeHttpRequestConfig(
    isNonArrayObject(loggingUrlIn) && isNonArrayObject(loggingUrlIn.http_request)
      ? { ...loggingUrlIn.http_request, __kv_scope: "logging" }
      : (isNonArrayObject(loggingUrlIn) ? loggingUrlIn.http_request : null),
    "$.debug.loggingEndpoint.http_request",
    problems,
    false
  );

  const tcrRequest = normalizeHttpRequestConfig(
    isNonArrayObject(tcrRequestRaw) ? { ...tcrRequestRaw, __kv_scope: "target" } : null,
    "$.targetCredentialRotation.request",
    problems,
    false
  );

  function checkAuthProfileRef(requestObj, path) {
    const profile =
      (requestObj?.http_authorization?.type === "key_rotation" && requestObj?.http_authorization?.profile) ||
      requestObj?.auth_profile ||
      null;
    if (!profile) return;
    if (!authProfilePrefix(profile)) {
      pushProblem(problems, `${path}.http_authorization.key_rotation.profile`, "profile name is not supported");
      return;
    }
    if (!httpAuthProfiles[profile]) {
      pushProblem(problems, `${path}.http_authorization.key_rotation.profile`, "must reference a defined http_auth profile");
    }
  }
  checkAuthProfileRef(jwtInboundHttpRequest, "$.jwt.inbound.http_request");
  checkAuthProfileRef(sinkHttpRequest, "$.debug.loggingEndpoint.http_request");
  checkAuthProfileRef(tcrRequest, "$.targetCredentialRotation.request");

  const headerForwardingIn = input.header_forwarding ?? {};
  if (!isNonArrayObject(headerForwardingIn)) {
    pushProblem(problems, "$.header_forwarding", "must be an object when provided");
  }
  if (isNonArrayObject(headerForwardingIn)) {
    ensureNoUnknownKeys(headerForwardingIn, new Set(["mode", "names"]), "$.header_forwarding", problems);
  }

  const mode = headerForwardingIn.mode === undefined ? "blacklist" : String(headerForwardingIn.mode).toLowerCase();
  if (!VALID_HEADER_FORWARDING_MODES.has(mode)) {
    pushProblem(problems, "$.header_forwarding.mode", "must be blacklist or whitelist");
  }

  const namesIn = headerForwardingIn.names === undefined ? DEFAULT_HEADER_FORWARDING_NAMES : headerForwardingIn.names;
  if (!Array.isArray(namesIn)) {
    pushProblem(problems, "$.header_forwarding.names", "must be an array");
  }
  const names = Array.isArray(namesIn)
    ? namesIn
        .map((name, index) => {
          if (typeof name !== "string") {
            pushProblem(problems, `$.header_forwarding.names[${index}]`, "must be a string");
            return "";
          }
          const normalized = normalizeHeaderName(name);
          if (!normalized) {
            pushProblem(problems, `$.header_forwarding.names[${index}]`, "must be non-empty");
            return "";
          }
          return normalized;
        })
        .filter(Boolean)
    : [];

  if (problems.length > 0) {
    throw new HttpError(400, "INVALID_CONFIG", "Configuration validation failed", {
      expected: CONFIG_SCHEMA_V1,
      problems,
    });
  }

  return {
    proxyName,
    http_requests,
    http_auth: {
      profiles: httpAuthProfiles,
    },
    jwt: {
      enabled: !!jwtEnabled,
      inbound: {
        enabled: !!jwtInboundEnabled,
        mode: jwtInboundMode,
        header: jwtInboundHeader || "Authorization",
        scheme: jwtInboundScheme || null,
        issuer: jwtInboundIssuer || null,
        audience: jwtInboundAudience || null,
        http_request: jwtInboundHttpRequest || null,
        clock_skew_seconds: Number.isInteger(jwtInboundSkew) ? jwtInboundSkew : 0,
      },
      outbound: {
        enabled: !!jwtOutboundEnabled,
        header: jwtOutboundHeader || "Authorization",
        scheme: jwtOutboundScheme || null,
        issuer: jwtOutboundIssuer || null,
        audience: jwtOutboundAudience || null,
        subject: jwtOutboundSubject || null,
        ttl_seconds: Number.isInteger(jwtOutboundTtl) ? jwtOutboundTtl : 3600,
      },
    },
    apiKeyPolicy: {
      proxyExpirySeconds,
      issuerExpirySeconds,
      adminExpirySeconds,
    },
    targetCredentialRotation: {
      enabled: !!tcrEnabled,
      strategy: tcrStrategy,
      request: tcrRequest || DEFAULT_CONFIG_V1.targetCredentialRotation.request,
      response: {
        key_path: tcrKeyPath,
        ttl_path: tcrTtlPath,
        ttl_unit: tcrTtlUnit,
        expires_at_path: tcrExpiresAtPath,
      },
      trigger: {
        refresh_skew_seconds: Number.isInteger(tcrSkew) && tcrSkew >= 0 ? tcrSkew : 300,
        retry_once_on_401: !!tcrRetry,
      },
    },
    debug: {
      max_debug_session_seconds: maxTtlSeconds,
      loggingEndpoint: {
        http_request: sinkHttpRequest || null,
      },
    },
    transform: {
      enabled,
      source_request: sourceRequestSection,
      target_response: targetResponseSection,
    },
    header_forwarding: {
      mode,
      names: [...new Set(names)],
    },
  };
}

async function parseYamlConfigText(yamlText) {
  if (typeof yamlText !== "string" || !yamlText.trim()) {
    throw new HttpError(400, "INVALID_CONFIG", "Configuration YAML must be a non-empty string");
  }
  const yaml = await loadYamlApi();
  let parsed;
  try {
    parsed = yaml.parse(yamlText);
  } catch (e) {
    throw new HttpError(400, "INVALID_CONFIG", "Configuration YAML could not be parsed", {
      cause: String(e?.message || e),
    });
  }
  return validateAndNormalizeConfigV1(parsed);
}

async function stringifyYamlConfig(configObj) {
  const yaml = await loadYamlApi();
  return yaml.stringify(configObj);
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function createConfigApi({ ensureKvBinding, kvStore, kvConfigYamlKey, kvConfigJsonKey }) {
  async function loadConfigV1(env) {
    ensureKvBinding(env);
    const bootstrapYaml = typeof env?.BOOTSTRAP_CONFIG_YAML === "string" ? env.BOOTSTRAP_CONFIG_YAML.trim() : "";
    if (bootstrapYaml) {
      let normalized;
      try {
        normalized = await parseYamlConfigText(bootstrapYaml);
      } catch (e) {
        if (e instanceof HttpError && e.code === "INVALID_CONFIG") {
          throw new HttpError(
            500,
            "INVALID_BOOTSTRAP_CONFIG",
            "BOOTSTRAP_CONFIG_YAML is invalid and could not be applied.",
            e.details || null
          );
        }
        throw e;
      }
      const [storedYaml, storedJson] = await Promise.all([kvStore(env).get(kvConfigYamlKey), kvStore(env).get(kvConfigJsonKey)]);
      const normalizedJson = JSON.stringify(normalized);
      if (storedYaml !== bootstrapYaml || storedJson !== normalizedJson) {
        await Promise.all([kvStore(env).put(kvConfigYamlKey, bootstrapYaml), kvStore(env).put(kvConfigJsonKey, normalizedJson)]);
      }
      return normalized;
    }
    const raw = await kvStore(env).get(kvConfigJsonKey);
    if (!raw) return deepClone(DEFAULT_CONFIG_V1);

    try {
      const parsed = JSON.parse(raw);
      return validateAndNormalizeConfigV1(parsed);
    } catch {
      throw new HttpError(500, "INVALID_STORED_CONFIG", "Stored configuration is invalid");
    }
  }

  async function loadConfigYamlV1(env) {
    ensureKvBinding(env);
    const bootstrapYaml = typeof env?.BOOTSTRAP_CONFIG_YAML === "string" ? env.BOOTSTRAP_CONFIG_YAML.trim() : "";
    if (bootstrapYaml) {
      return bootstrapYaml;
    }
    const raw = await kvStore(env).get(kvConfigYamlKey);
    if (raw) return raw;
    const config = await loadConfigV1(env);
    return stringifyYamlConfig(config);
  }

  async function saveConfigFromYamlV1(yamlText, env) {
    ensureKvBinding(env);
    const normalized = await parseYamlConfigText(yamlText);
    await Promise.all([
      kvStore(env).put(kvConfigYamlKey, yamlText),
      kvStore(env).put(kvConfigJsonKey, JSON.stringify(normalized)),
    ]);
    return normalized;
  }

  async function saveConfigObjectV1(configObj, env) {
    ensureKvBinding(env);
    const normalized = validateAndNormalizeConfigV1(configObj);
    const yamlText = await stringifyYamlConfig(normalized);
    await Promise.all([
      kvStore(env).put(kvConfigYamlKey, yamlText),
      kvStore(env).put(kvConfigJsonKey, JSON.stringify(normalized)),
    ]);
    return normalized;
  }

  return {
    loadConfigV1,
    loadConfigYamlV1,
    saveConfigFromYamlV1,
    saveConfigObjectV1,
  };
}

export {
  CONFIG_SCHEMA_V1,
  DEFAULT_HEADER_FORWARDING_NAMES,
  DEFAULT_CONFIG_V1,
  VALID_FALLBACK_VALUES,
  VALID_HEADER_FORWARDING_MODES,
  VALID_JWT_INBOUND_MODES,
  VALID_TRANSFORM_TYPES,
  createConfigApi,
  parseYamlConfigText,
  stringifyYamlConfig,
  validateAndNormalizeConfigV1,
};
