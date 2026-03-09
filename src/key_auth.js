import { HttpError } from "./lib.js";

function createKeyAuthApi({
  constants,
  ensureKvBinding,
  kvStore,
  kvGetValue,
  kvPutValue,
  loadConfigV1,
  getEnvInt,
  defaults,
  reservedRoot,
  generateSecret,
  parseMs,
  capitalize,
  escapeHtml,
  htmlPage,
  jsonResponse,
  signJwtHs256,
  verifyJwtHs256,
}) {
  function keyKindConfig(kind) {
    if (kind === "proxy") {
      return {
        current: constants.KV_PROXY_KEY,
        old: constants.KV_PROXY_KEY_OLD,
        oldExpiresAt: constants.KV_PROXY_KEY_OLD_EXPIRES_AT,
        primaryCreatedAt: constants.KV_PROXY_PRIMARY_KEY_CREATED_AT,
        secondaryCreatedAt: constants.KV_PROXY_SECONDARY_KEY_CREATED_AT,
        header: "X-Proxy-Key",
        missingCode: "NOT_INITIALIZED",
        missingMessage: `Proxy not initialized. Visit ${reservedRoot} first.`,
        unauthorizedCode: "UNAUTHORIZED",
        unauthorizedMessage: "Missing or invalid X-Proxy-Key",
        policyKey: "proxyExpirySeconds",
        responseKey: "proxy_key",
      };
    }
    if (kind === "issuer") {
      return {
        current: constants.KV_ISSUER_KEY,
        old: constants.KV_ISSUER_KEY_OLD,
        oldExpiresAt: constants.KV_ISSUER_KEY_OLD_EXPIRES_AT,
        primaryCreatedAt: constants.KV_ISSUER_PRIMARY_KEY_CREATED_AT,
        secondaryCreatedAt: constants.KV_ISSUER_SECONDARY_KEY_CREATED_AT,
        header: "X-Issuer-Key",
        missingCode: "ISSUER_NOT_CONFIGURED",
        missingMessage: "Issuer key is not initialized.",
        unauthorizedCode: "UNAUTHORIZED_ISSUER",
        unauthorizedMessage: "Missing or invalid X-Issuer-Key",
        policyKey: "issuerExpirySeconds",
        responseKey: "issuer_key",
      };
    }
    if (kind === "admin") {
      return {
        current: constants.KV_ADMIN_KEY,
        old: constants.KV_ADMIN_KEY_OLD,
        oldExpiresAt: constants.KV_ADMIN_KEY_OLD_EXPIRES_AT,
        primaryCreatedAt: constants.KV_ADMIN_PRIMARY_KEY_CREATED_AT,
        secondaryCreatedAt: constants.KV_ADMIN_SECONDARY_KEY_CREATED_AT,
        header: "X-Admin-Key",
        missingCode: "ADMIN_NOT_CONFIGURED",
        missingMessage: "Admin key is not initialized.",
        unauthorizedCode: "UNAUTHORIZED_ADMIN",
        unauthorizedMessage: "Missing or invalid X-Admin-Key",
        policyKey: "adminExpirySeconds",
        responseKey: "admin_key",
      };
    }
    throw new HttpError(404, "INVALID_KEY_KIND", "Invalid key kind", {
      expected: ["proxy", "issuer", "admin"],
      received: kind,
    });
  }

  async function getKeyAuthState(kind, env) {
    const cfg = keyKindConfig(kind);
    ensureKvBinding(env);
    const [current, old, oldExpiresAtRaw, primaryCreatedAtRaw, secondaryCreatedAtRaw] = await Promise.all([
      kvGetValue(env, cfg.current),
      kvGetValue(env, cfg.old),
      kvStore(env).get(cfg.oldExpiresAt),
      kvStore(env).get(cfg.primaryCreatedAt),
      kvStore(env).get(cfg.secondaryCreatedAt),
    ]);
    const oldExpiresAt = Number(oldExpiresAtRaw || 0);
    const primaryCreatedAt = Number(primaryCreatedAtRaw || 0);
    const secondaryCreatedAt = Number(secondaryCreatedAtRaw || 0);
    return { cfg, current, old, oldExpiresAt, primaryCreatedAt, secondaryCreatedAt };
  }

  async function requireKeyKind(request, env, kind) {
    const { cfg, current, old, oldExpiresAt, primaryCreatedAt, secondaryCreatedAt } = await getKeyAuthState(kind, env);
    if (!current) {
      const details = kind === "admin" ? { setup: `Visit ${reservedRoot} to bootstrap keys.` } : null;
      throw new HttpError(503, cfg.missingCode, cfg.missingMessage, details);
    }

    const got = request.headers.get(cfg.header) || "";

    const cfgDoc = await loadConfigV1(env);
    const expirySeconds = cfgDoc?.apiKeyPolicy?.[cfg.policyKey] ?? null;
    const now = Date.now();
    const primaryExpired =
      expirySeconds !== null &&
      Number.isFinite(primaryCreatedAt) &&
      primaryCreatedAt > 0 &&
      primaryCreatedAt + Number(expirySeconds) * 1000 <= now;
    if (primaryExpired && got === current) {
      throw new HttpError(401, cfg.unauthorizedCode, `${cfg.unauthorizedMessage} (primary key expired)`);
    }
    if (got === current) return;

    const oldActive = !!old && Number.isFinite(oldExpiresAt) && oldExpiresAt > now;
    const secondaryExpired =
      expirySeconds !== null &&
      Number.isFinite(secondaryCreatedAt) &&
      secondaryCreatedAt > 0 &&
      secondaryCreatedAt + Number(expirySeconds) * 1000 <= now;
    if (oldActive && !secondaryExpired && got === old) return;

    if (!!old && Number.isFinite(oldExpiresAt) && oldExpiresAt <= now) {
      await Promise.all([kvStore(env).delete(cfg.old), kvStore(env).delete(cfg.oldExpiresAt), kvStore(env).delete(cfg.secondaryCreatedAt)]);
    }

    if (old && Number.isFinite(oldExpiresAt) && oldExpiresAt > now) {
      throw new HttpError(401, cfg.unauthorizedCode, `${cfg.unauthorizedMessage} (old key overlap is active)`);
    }
    throw new HttpError(401, cfg.unauthorizedCode, cfg.unauthorizedMessage);
  }

  async function requireProxyKey(request, env) {
    await requireKeyKind(request, env, "proxy");
  }

  async function requireAdminKey(request, env) {
    await requireKeyKind(request, env, "admin");
  }

  async function requireIssuerKey(request, env) {
    await requireKeyKind(request, env, "issuer");
  }

  async function getIssuerKeyState(env) {
    const state = await getKeyAuthState("issuer", env);
    if (!state.current) {
      const cfg = keyKindConfig("issuer");
      throw new HttpError(503, cfg.missingCode, cfg.missingMessage);
    }
    return state;
  }

  async function getProxyKey(env) {
    ensureKvBinding(env);
    return kvGetValue(env, constants.KV_PROXY_KEY);
  }

  async function getAdminKey(env) {
    ensureKvBinding(env);
    return kvGetValue(env, constants.KV_ADMIN_KEY);
  }

  function getAdminAccessTokenFromRequest(request) {
    const explicit = String(request.headers.get("X-Admin-Access-Token") || "").trim();
    if (explicit) return explicit;
    const auth = String(request.headers.get("authorization") || "");
    const match = auth.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : "";
  }

  async function getAdminJwtSecret(env) {
    const configured = String(env?.ADMIN_UI_JWT_SECRET || "").trim();
    if (configured) return configured;
    const adminKey = await getAdminKey(env);
    if (!adminKey) {
      throw new HttpError(503, "ADMIN_NOT_CONFIGURED", "Admin key is not initialized.", {
        setup: `Visit ${reservedRoot} to bootstrap keys.`,
      });
    }
    return adminKey;
  }

  async function validateAdminAccessToken(token, env) {
    if (!token) return false;
    const secret = await getAdminJwtSecret(env);
    try {
      await verifyJwtHs256(token, secret, { issuer: "apiproxy", audience: "apiproxy-admin-ui", clock_skew_seconds: 0 });
      return true;
    } catch {
      return false;
    }
  }

  async function requireAdminAuth(request, env) {
    const token = getAdminAccessTokenFromRequest(request);
    if (token) {
      const ok = await validateAdminAccessToken(token, env);
      if (ok) return;
      throw new HttpError(401, "UNAUTHORIZED_ADMIN", "Invalid or expired admin access token");
    }
    await requireAdminKey(request, env);
  }

  async function handleAdminAccessTokenPost(env) {
    const ttlSeconds = Math.max(60, getEnvInt(env, "ADMIN_ACCESS_TOKEN_TTL_SECONDS", defaults.ADMIN_ACCESS_TOKEN_TTL_SECONDS));
    const nowSec = Math.floor(Date.now() / 1000);
    const expiresAtMs = (nowSec + ttlSeconds) * 1000;
    const secret = await getAdminJwtSecret(env);
    const token = await signJwtHs256(
      {
        iss: "apiproxy",
        aud: "apiproxy-admin-ui",
        iat: nowSec,
        exp: nowSec + ttlSeconds,
        scope: "admin_ui",
      },
      secret
    );
    return jsonResponse(200, {
      ok: true,
      data: {
        access_token: token,
        expires_at_ms: expiresAtMs,
        ttl_seconds: ttlSeconds,
      },
      meta: {},
    });
  }

  async function handleRotateByKind(kind, request, env) {
    const cfg = keyKindConfig(kind);
    const overlapMs = getEnvInt(env, "ROTATE_OVERLAP_MS", defaults.ROTATE_OVERLAP_MS);
    const now = Date.now();
    const oldExpiresAt = now + Math.max(0, overlapMs);
    const [state, config] = await Promise.all([getKeyAuthState(kind, env), loadConfigV1(env)]);
    const current = state.current;
    const currentPrimaryCreatedAt = parseMs(state.primaryCreatedAt);
    const newKey = generateSecret();
    const expirySeconds = config?.apiKeyPolicy?.[cfg.policyKey] ?? null;

    await Promise.all([kvPutValue(env, cfg.current, newKey), kvStore(env).put(cfg.primaryCreatedAt, String(now))]);
    if (current && overlapMs > 0) {
      await Promise.all([
        kvPutValue(env, cfg.old, current),
        kvStore(env).put(cfg.oldExpiresAt, String(oldExpiresAt)),
        kvStore(env).put(cfg.secondaryCreatedAt, String(currentPrimaryCreatedAt || now)),
      ]);
    } else {
      await Promise.all([kvStore(env).delete(cfg.old), kvStore(env).delete(cfg.oldExpiresAt), kvStore(env).delete(cfg.secondaryCreatedAt)]);
    }

    const acceptsHtml = (request.headers.get("accept") || "").includes("text/html");
    if (acceptsHtml) {
      return new Response(
        htmlPage(
          `${capitalize(kind)} key rotated`,
          `<p>Store this new ${escapeHtml(kind)} key and replace the old value immediately.</p>
           <pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-all;">${escapeHtml(
             newKey
           )}</pre>`
        ),
        { headers: { "content-type": "text/html; charset=utf-8" } }
      );
    }

    return jsonResponse(200, {
      ok: true,
      data: {
        kind,
        [cfg.responseKey]: newKey,
        old_key_overlap_active: !!current && overlapMs > 0,
        old_key_overlap_ms: current ? Math.max(0, overlapMs) : 0,
        expiry_seconds: expirySeconds,
      },
    });
  }

  return {
    keyKindConfig,
    getKeyAuthState,
    requireKeyKind,
    getProxyKey,
    getAdminKey,
    getIssuerKeyState,
    requireProxyKey,
    requireAdminKey,
    requireIssuerKey,
    getAdminAccessTokenFromRequest,
    getAdminJwtSecret,
    validateAdminAccessToken,
    requireAdminAuth,
    handleAdminAccessTokenPost,
    handleRotateByKind,
  };
}

export { createKeyAuthApi };
