import { HttpError } from "./lib.js";

const DEFAULT_SECURITY_POLICY = {
  require_https: true,
  block_private_networks: true,
  method_allowlist: null,
  timeout_ms: null,
  max_response_bytes: null,
  allowed_hosts: null,
};

function normalizeHost(raw) {
  const value = String(raw || "").trim().toLowerCase();
  if (!value) return "";
  try {
    const u = new URL(value);
    return u.hostname.toLowerCase();
  } catch {
    return value;
  }
}

function getAllowedHostsFromEnv(env, fallbackRaw = "") {
  const raw = String(env?.ALLOWED_HOSTS ?? fallbackRaw ?? "").trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((h) => normalizeHost(h))
    .filter(Boolean);
}

function normalizeRequestSecurityConfig(securityIn, path = "$.security") {
  const problems = [];
  function add(subPath, message) {
    problems.push({ path: subPath, message });
  }
  if (securityIn === undefined || securityIn === null) {
    return { value: null, problems };
  }
  if (typeof securityIn !== "object" || Array.isArray(securityIn)) {
    add(path, "must be an object");
    return { value: null, problems };
  }
  const allowed = new Set(["require_https", "block_private_networks", "method_allowlist", "timeout_ms", "max_response_bytes", "allowed_hosts"]);
  for (const key of Object.keys(securityIn)) {
    if (!allowed.has(key)) add(`${path}.${key}`, "unknown field");
  }
  const out = {};
  if (securityIn.require_https !== undefined) {
    if (typeof securityIn.require_https !== "boolean") add(`${path}.require_https`, "must be a boolean");
    else out.require_https = securityIn.require_https;
  }
  if (securityIn.block_private_networks !== undefined) {
    if (typeof securityIn.block_private_networks !== "boolean") add(`${path}.block_private_networks`, "must be a boolean");
    else out.block_private_networks = securityIn.block_private_networks;
  }
  if (securityIn.method_allowlist !== undefined) {
    if (!Array.isArray(securityIn.method_allowlist)) {
      add(`${path}.method_allowlist`, "must be an array");
    } else {
      out.method_allowlist = securityIn.method_allowlist
        .map((m, i) => {
          if (typeof m !== "string" || !m.trim()) {
            add(`${path}.method_allowlist[${i}]`, "must be a non-empty string");
            return "";
          }
          return m.trim().toUpperCase();
        })
        .filter(Boolean);
    }
  }
  if (securityIn.timeout_ms !== undefined) {
    if (securityIn.timeout_ms === null) out.timeout_ms = null;
    else {
      const n = Number(securityIn.timeout_ms);
      if (!Number.isInteger(n) || n <= 0) add(`${path}.timeout_ms`, "must be a positive integer or null");
      else out.timeout_ms = n;
    }
  }
  if (securityIn.max_response_bytes !== undefined) {
    if (securityIn.max_response_bytes === null) out.max_response_bytes = null;
    else {
      const n = Number(securityIn.max_response_bytes);
      if (!Number.isInteger(n) || n <= 0) add(`${path}.max_response_bytes`, "must be a positive integer or null");
      else out.max_response_bytes = n;
    }
  }
  if (securityIn.allowed_hosts !== undefined) {
    if (!Array.isArray(securityIn.allowed_hosts)) {
      add(`${path}.allowed_hosts`, "must be an array");
    } else {
      out.allowed_hosts = securityIn.allowed_hosts
        .map((h, i) => {
          const value = String(h || "").trim().toLowerCase();
          if (!value) {
            add(`${path}.allowed_hosts[${i}]`, "must be a non-empty string");
            return "";
          }
          return normalizeHost(value);
        })
        .filter(Boolean);
    }
  }
  return { value: out, problems };
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

function inspectRequestSecurityViolations(requestPath, reqModel) {
  const violations = [];
  const policy = { ...DEFAULT_SECURITY_POLICY, ...readPolicyFromRequestModel(reqModel) };
  const rawUrl = String(reqModel?.url || "").trim();
  if (!rawUrl) return violations;

  let targetUrl;
  try {
    targetUrl = new URL(rawUrl);
  } catch {
    return violations;
  }

  const host = String(targetUrl.hostname || "").toLowerCase();
  if (policy.require_https !== false && targetUrl.protocol !== "https:") {
    violations.push({
      path: `${requestPath}.security.require_https`,
      message: "guardrail violation: URL is not https. Set security.require_https=false only if you explicitly accept insecure outbound transport.",
    });
  }

  if (policy.block_private_networks !== false) {
    if (host === "localhost" || host.endsWith(".localhost")) {
      violations.push({
        path: `${requestPath}.security.block_private_networks`,
        message: "guardrail violation: localhost target is blocked by default. Set security.block_private_networks=false only if this is intentional.",
      });
    } else if (isIpLiteral(host) && (isPrivateOrLinkLocalIp(host) || host === "169.254.169.254")) {
      violations.push({
        path: `${requestPath}.security.block_private_networks`,
        message: "guardrail violation: private/link-local IP target is blocked by default. Set security.block_private_networks=false only if this is intentional.",
      });
    }
  }

  return violations;
}

function readPolicyFromRequestModel(reqModel) {
  const sec = reqModel?.security;
  if (!sec || typeof sec !== "object") return { ...DEFAULT_SECURITY_POLICY };
  const merged = { ...DEFAULT_SECURITY_POLICY };
  if (typeof sec.require_https === "boolean") merged.require_https = sec.require_https;
  if (typeof sec.block_private_networks === "boolean") merged.block_private_networks = sec.block_private_networks;
  if (Array.isArray(sec.method_allowlist)) {
    merged.method_allowlist = sec.method_allowlist.map((m) => String(m || "").trim().toUpperCase()).filter(Boolean);
  }
  if (Number.isInteger(Number(sec.timeout_ms)) && Number(sec.timeout_ms) > 0) {
    merged.timeout_ms = Number(sec.timeout_ms);
  } else if (sec.timeout_ms === null) {
    merged.timeout_ms = null;
  }
  if (Number.isInteger(Number(sec.max_response_bytes)) && Number(sec.max_response_bytes) > 0) {
    merged.max_response_bytes = Number(sec.max_response_bytes);
  } else if (sec.max_response_bytes === null) {
    merged.max_response_bytes = null;
  }
  if (Array.isArray(sec.allowed_hosts)) {
    const hosts = sec.allowed_hosts.map(normalizeHost).filter(Boolean);
    merged.allowed_hosts = hosts.length ? hosts : null;
  }
  return merged;
}

function assertOutboundRequestPolicy({ url, method, policy, envAllowedHosts }) {
  const p = policy || DEFAULT_SECURITY_POLICY;
  const target = url instanceof URL ? url : new URL(String(url || ""));
  const host = String(target.hostname || "").toLowerCase();
  const upperMethod = String(method || "GET").toUpperCase();

  if (p.require_https && target.protocol !== "https:") {
    throw new HttpError(400, "UPSTREAM_PROTOCOL_NOT_ALLOWED", "Upstream URL must use https");
  }

  if (Array.isArray(p.method_allowlist) && p.method_allowlist.length > 0 && !p.method_allowlist.includes(upperMethod)) {
    throw new HttpError(403, "UPSTREAM_METHOD_NOT_ALLOWED", `Method not allowed by outbound security policy: ${upperMethod}`);
  }

  const mergedAllowedHosts = [];
  if (Array.isArray(envAllowedHosts) && envAllowedHosts.length > 0) mergedAllowedHosts.push(...envAllowedHosts);
  if (Array.isArray(p.allowed_hosts) && p.allowed_hosts.length > 0) mergedAllowedHosts.push(...p.allowed_hosts);
  if (mergedAllowedHosts.length > 0 && !mergedAllowedHosts.includes(host)) {
    throw new HttpError(403, "UPSTREAM_HOST_NOT_ALLOWED", `Upstream host not allowlisted: ${host}`);
  }

  if (p.block_private_networks) {
    if (host === "localhost" || host.endsWith(".localhost")) {
      throw new HttpError(403, "UPSTREAM_HOST_BLOCKED", "localhost is blocked");
    }
    if (isIpLiteral(host) && (isPrivateOrLinkLocalIp(host) || host === "169.254.169.254")) {
      throw new HttpError(403, "UPSTREAM_IP_BLOCKED", "Private/link-local IPs are blocked");
    }
  }
}

async function fetchWithPolicy(url, init, policy, fetchImpl = fetch) {
  const timeoutMs = Number(policy?.timeout_ms || 0);
  if (!timeoutMs) return fetchImpl(url, init);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function createOutboundSecurityApi() {
  return {
    defaultPolicy: DEFAULT_SECURITY_POLICY,
    getAllowedHostsFromEnv,
    normalizeRequestSecurityConfig,
    inspectRequestSecurityViolations,
    readPolicyFromRequestModel,
    assertOutboundRequestPolicy,
    fetchWithPolicy,
  };
}

export {
  createOutboundSecurityApi,
  DEFAULT_SECURITY_POLICY,
  normalizeRequestSecurityConfig,
  inspectRequestSecurityViolations,
};
