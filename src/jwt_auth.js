import { HttpError, normalizeHeaderName } from "./lib.js";

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlEncodeString(value) {
  const enc = new TextEncoder();
  return base64UrlEncodeBytes(enc.encode(value));
}

function base64UrlDecodeToBytes(value) {
  const padded = String(value || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(String(value || "").length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function parseJwtToken(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    throw new HttpError(401, "JWT_INVALID", "JWT must have three segments");
  }
  const [headerB64, payloadB64, sigB64] = parts;
  let header;
  let payload;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecodeToBytes(headerB64)));
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecodeToBytes(payloadB64)));
  } catch {
    throw new HttpError(401, "JWT_INVALID", "JWT header or payload is not valid JSON");
  }
  return {
    header,
    payload,
    signature: base64UrlDecodeToBytes(sigB64),
    signingInput: `${headerB64}.${payloadB64}`,
  };
}

function extractJwtFromHeaders(headers, config) {
  const headerName = normalizeHeaderName(config?.header || "authorization");
  if (!headerName) throw new HttpError(401, "JWT_INVALID", "JWT header name is invalid");
  const raw = headers.get(headerName) || headers.get(headerName.toLowerCase()) || "";
  if (!raw) throw new HttpError(401, "JWT_MISSING", "JWT header is missing");
  const scheme = typeof config?.scheme === "string" ? config.scheme.trim() : "Bearer";
  if (!scheme) return raw.trim();
  const match = raw.match(new RegExp(`^${scheme}\\s+(.+)$`, "i"));
  if (!match) throw new HttpError(401, "JWT_INVALID", `JWT header must use ${scheme} scheme`);
  return match[1].trim();
}

function assertJwtClaims(payload, cfg) {
  const nowSec = Math.floor(Date.now() / 1000);
  const skew = Number(cfg?.clock_skew_seconds || 0);

  if (payload.exp !== undefined) {
    const exp = Number(payload.exp);
    if (!Number.isFinite(exp)) throw new HttpError(401, "JWT_INVALID", "JWT exp claim is invalid");
    if (nowSec - skew >= exp) throw new HttpError(401, "JWT_EXPIRED", "JWT has expired");
  }
  if (payload.nbf !== undefined) {
    const nbf = Number(payload.nbf);
    if (!Number.isFinite(nbf)) throw new HttpError(401, "JWT_INVALID", "JWT nbf claim is invalid");
    if (nowSec + skew < nbf) throw new HttpError(401, "JWT_NOT_ACTIVE", "JWT is not active yet");
  }
  if (payload.iss && cfg?.issuer && String(payload.iss) !== String(cfg.issuer)) {
    throw new HttpError(401, "JWT_INVALID", "JWT issuer mismatch");
  }
  if (cfg?.audience) {
    const aud = payload.aud;
    const want = String(cfg.audience);
    if (Array.isArray(aud)) {
      if (!aud.map(String).includes(want)) throw new HttpError(401, "JWT_INVALID", "JWT audience mismatch");
    } else if (aud !== undefined && String(aud) !== want) {
      throw new HttpError(401, "JWT_INVALID", "JWT audience mismatch");
    } else if (aud === undefined) {
      throw new HttpError(401, "JWT_INVALID", "JWT audience missing");
    }
  }
}

function createJwtAuthApi({
  buildHttpRequestInit,
  jwksCacheTtlMs = 5 * 60 * 1000,
}) {
  let jwksCache = { url: "", fetchedAt: 0, keys: [] };

  async function fetchJwks(requestConfig, config, env) {
    const url = String(requestConfig?.url || "").trim();
    if (!url) {
      throw new HttpError(401, "JWT_INVALID", "JWKS request URL is required");
    }
    const now = Date.now();
    if (jwksCache.url === url && now - jwksCache.fetchedAt < jwksCacheTtlMs) {
      return jwksCache.keys;
    }

    let res;
    try {
      const init = await buildHttpRequestInit(requestConfig, config, env);
      res = await fetch(url, init);
    } catch {
      throw new HttpError(502, "JWKS_FETCH_FAILED", "Failed to fetch JWKS");
    }
    if (!res.ok) {
      throw new HttpError(502, "JWKS_FETCH_FAILED", "Failed to fetch JWKS", { status: res.status });
    }
    const data = await res.json();
    const keys = Array.isArray(data?.keys) ? data.keys : [];
    jwksCache = { url, fetchedAt: now, keys };
    return keys;
  }

  async function verifyJwtHs256(token, secret, cfg) {
    const { header, payload, signature, signingInput } = parseJwtToken(token);
    if (String(header.alg || "").toUpperCase() !== "HS256") {
      throw new HttpError(401, "JWT_INVALID", "JWT alg must be HS256");
    }
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("HMAC", key, signature, enc.encode(signingInput));
    if (!ok) throw new HttpError(401, "JWT_INVALID", "JWT signature invalid");
    assertJwtClaims(payload, cfg);
    return payload;
  }

  async function verifyJwtRs256(token, cfg, config, env) {
    const { header, payload, signature, signingInput } = parseJwtToken(token);
    if (String(header.alg || "").toUpperCase() !== "RS256") {
      throw new HttpError(401, "JWT_INVALID", "JWT alg must be RS256");
    }

    const reqCfg = cfg?.http_request;
    if (!reqCfg || typeof reqCfg !== "object") {
      throw new HttpError(401, "JWT_INVALID", "jwt.inbound.http_request is required for jwks mode");
    }

    const keys = await fetchJwks(reqCfg, config, env);
    if (!keys.length) throw new HttpError(401, "JWT_INVALID", "No JWKS keys available");

    const kid = header.kid ? String(header.kid) : "";
    let candidates = keys.filter((k) => String(k?.kty || "").toUpperCase() === "RSA");
    if (kid) {
      candidates = candidates.filter((k) => String(k?.kid || "") === kid);
    }
    if (!candidates.length) {
      throw new HttpError(401, "JWT_INVALID", kid ? "No matching JWKS key for kid" : "No RSA JWKS keys available");
    }

    const enc = new TextEncoder();
    let verified = false;
    for (const jwk of candidates) {
      try {
        const key = await crypto.subtle.importKey(
          "jwk",
          jwk,
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["verify"]
        );
        const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, enc.encode(signingInput));
        if (ok) {
          verified = true;
          break;
        }
      } catch {
        // Ignore malformed candidate keys and continue trying others.
      }
    }

    if (!verified) throw new HttpError(401, "JWT_INVALID", "JWT signature invalid");
    assertJwtClaims(payload, cfg);
    return payload;
  }

  async function signJwtHs256(payload, secret) {
    const header = { alg: "HS256", typ: "JWT" };
    const headerB64 = base64UrlEncodeString(JSON.stringify(header));
    const payloadB64 = base64UrlEncodeString(JSON.stringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(signingInput));
    const sigB64 = base64UrlEncodeBytes(new Uint8Array(sig));
    return `${signingInput}.${sigB64}`;
  }

  return {
    extractJwtFromHeaders,
    verifyJwtHs256,
    verifyJwtRs256,
    signJwtHs256,
  };
}

export { createJwtAuthApi };
