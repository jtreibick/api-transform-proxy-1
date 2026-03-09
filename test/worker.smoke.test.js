import test from "node:test";
import assert from "node:assert/strict";

import worker from "../src/index.js";
import runtimeWorker from "../src/runtime_entry.js";
import controlWorker from "../src/control_entry.js";
const SERIAL = { concurrency: false };

function createMockKvBinding(initial = {}) {
  const store = new Map(Object.entries(initial));

  return {
    _store: store,
    async get(key, options) {
      const value = store.get(String(key));
      if (value === undefined) return null;
      if (options && options.type === "json") {
        try {
          return JSON.parse(String(value));
        } catch {
          return null;
        }
      }
      return value;
    },
    async put(key, value) {
      store.set(String(key), String(value));
    },
    async delete(key) {
      store.delete(String(key));
    },
    async list(options = {}) {
      const prefix = String(options.prefix || "");
      const keys = [];
      for (const name of store.keys()) {
        if (!prefix || name.startsWith(prefix)) keys.push({ name });
      }
      keys.sort((a, b) => a.name.localeCompare(b.name));
      return { keys, list_complete: true, cursor: "" };
    },
  };
}

function createEnv(vars = {}, initialKv = {}) {
  return {
    CONFIG: createMockKvBinding(initialKv),
    BUILD_TIMESTAMP: "dev",
    ...vars,
  };
}

function minimalValidConfigPatch(extra = {}) {
  return {
    http_requests: {
      outbound_proxy: {
        method: "GET",
        url: "https://example.com",
        headers: {},
        body: { type: "none" },
      },
    },
    targetCredentialRotation: {
      response: {
        ttl_path: "data.ttl",
      },
    },
    ...extra,
  };
}

function createCtx() {
  return {
    waitUntil() {},
  };
}

async function callWorker(env, { method = "GET", path = "/_apiproxy", headers = {}, body } = {}) {
  const url = `https://example.workers.dev${path}`;
  const request = new Request(url, {
    method,
    headers,
    body,
  });
  return worker.fetch(request, env, createCtx());
}

async function callSpecificWorker(workerImpl, env, { method = "GET", path = "/_apiproxy", headers = {}, body } = {}) {
  const url = `https://example.workers.dev${path}`;
  const request = new Request(url, {
    method,
    headers,
    body,
  });
  return workerImpl.fetch(request, env, createCtx());
}

async function bootstrapKeys(env) {
  const response = await callWorker(env, { method: "GET", path: "/_apiproxy/" });
  assert.equal(response.status, 200);
  const proxyKey = await env.CONFIG.get("proxy_key");
  const adminKey = await env.CONFIG.get("admin_key");
  assert.ok(proxyKey);
  assert.ok(adminKey);
  return { proxyKey, adminKey };
}

test("GET /_apiproxy initializes missing keys and serves onboarding HTML", SERIAL, async () => {
  const env = createEnv();

  const response = await callWorker(env, { method: "GET", path: "/_apiproxy/" });

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") || "", /text\/html/i);
  const html = await response.text();
  assert.match(html, /API Transform Proxy/i);
  assert.match(html, /API Key \(New\)/i);
  assert.ok(await env.CONFIG.get("proxy_key"));
  assert.ok(await env.CONFIG.get("admin_key"));
});

test("POST /_apiproxy/request without proxy key returns UNAUTHORIZED", SERIAL, async () => {
  const env = createEnv();
  await bootstrapKeys(env);

  const response = await callWorker(env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      upstream: {
        method: "GET",
        url: "/json",
      },
    }),
  });

  assert.equal(response.status, 401);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "UNAUTHORIZED");
});

test("POST /_apiproxy/request with invalid payload returns INVALID_REQUEST", SERIAL, async () => {
  const env = createEnv();
  const { proxyKey } = await bootstrapKeys(env);

  const response = await callWorker(env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
    },
    body: JSON.stringify({
      upstream: {
        method: "NOPE",
        url: "https://example.com/json",
      },
    }),
  });

  assert.equal(response.status, 400);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "INVALID_REQUEST");
});

test("POST /_apiproxy/request valid passthrough returns ok envelope", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { proxyKey } = await bootstrapKeys(env);

  const realFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ hello: "world" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });

  try {
    const response = await callWorker(env, {
      method: "POST",
      path: "/_apiproxy/request",
      headers: {
        "content-type": "application/json",
        "x-proxy-key": proxyKey,
      },
      body: JSON.stringify({
        upstream: {
          method: "GET",
          url: "/json",
        },
      }),
    });

    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload?.ok, true);
    assert.deepEqual(payload?.data, { hello: "world" });
    assert.equal(payload?.meta?.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("ROTATE_OVERLAP_MS=0 invalidates old proxy key immediately after rotate", SERIAL, async () => {
  const env = createEnv({ ROTATE_OVERLAP_MS: "0" }, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { proxyKey: oldKey } = await bootstrapKeys(env);

  const rotateResponse = await callWorker(env, {
    method: "POST",
    path: "/_apiproxy/keys/proxy/rotate",
    headers: {
      "x-proxy-key": oldKey,
    },
  });

  assert.equal(rotateResponse.status, 200);
  const rotatePayload = await rotateResponse.json();
  const newKey = rotatePayload?.data?.proxy_key;
  assert.ok(newKey);
  assert.notEqual(newKey, oldKey);

  const deniedResponse = await callWorker(env, {
    method: "POST",
    path: "/_apiproxy/request",
      headers: {
        "content-type": "application/json",
        "x-proxy-key": oldKey,
      },
    body: JSON.stringify({
      upstream: {
        method: "GET",
        url: "https://example.com/json",
      },
    }),
  });

  assert.equal(deniedResponse.status, 401);
  const deniedPayload = await deniedResponse.json();
  assert.equal(deniedPayload?.error?.code, "UNAUTHORIZED");

  const realFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ ok: 1 }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });

  try {
    const allowedResponse = await callWorker(env, {
      method: "POST",
      path: "/_apiproxy/request",
      headers: {
        "content-type": "application/json",
        "x-proxy-key": newKey,
      },
      body: JSON.stringify({
        upstream: {
          method: "GET",
          url: "/json",
        },
      }),
    });

    assert.equal(allowedResponse.status, 200);
    const allowedPayload = await allowedResponse.json();
    assert.equal(allowedPayload?.ok, true);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("Missing configured outbound target host returns MISSING_TARGET_HOST_CONFIG", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch({
      http_requests: {},
    })),
  });
  const { proxyKey } = await bootstrapKeys(env);

  const response = await callWorker(env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
    },
    body: JSON.stringify({
      upstream: {
        method: "GET",
        url: "/json",
      },
    }),
  });

  assert.equal(response.status, 503);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "MISSING_TARGET_HOST_CONFIG");
});

test("Admin endpoints accept both X-Admin-Key and bearer access token", SERIAL, async () => {
  const env = createEnv();
  const { adminKey } = await bootstrapKeys(env);

  const byKeyResponse = await callWorker(env, {
    method: "GET",
    path: "/_apiproxy/admin/version",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(byKeyResponse.status, 200);

  const tokenResponse = await callWorker(env, {
    method: "POST",
    path: "/_apiproxy/admin/access-token",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(tokenResponse.status, 200);
  const tokenPayload = await tokenResponse.json();
  const token = tokenPayload?.data?.access_token;
  assert.ok(token);

  const byBearerResponse = await callWorker(env, {
    method: "GET",
    path: "/_apiproxy/admin/version",
    headers: {
      authorization: `Bearer ${token}`,
    },
  });
  assert.equal(byBearerResponse.status, 200);
});

test("Admin config PUT roundtrip is reflected in status page", SERIAL, async (t) => {
  try {
    await import("yaml");
  } catch {
    t.skip("yaml dependency is unavailable in this local test environment");
    return;
  }

  const env = createEnv();
  const { adminKey } = await bootstrapKeys(env);

  const putResponse = await callWorker(env, {
    method: "PUT",
    path: "/_apiproxy/admin/config",
    headers: {
      "x-admin-key": adminKey,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      ...minimalValidConfigPatch({
        proxyName: "Smoke Test Proxy",
        targetHost: "https://config.example",
      }),
    }),
  });
  assert.equal(putResponse.status, 200);

  const statusResponse = await callWorker(env, {
    method: "GET",
    path: "/_apiproxy/",
  });
  assert.equal(statusResponse.status, 200);
  const html = await statusResponse.text();
  assert.match(html, /Smoke Test Proxy/);
});

test("Live log stream returns LOGGING_DISABLED when debug is off", SERIAL, async () => {
  const env = createEnv();
  const { adminKey } = await bootstrapKeys(env);

  const response = await callWorker(env, {
    method: "GET",
    path: "/_apiproxy/admin/live-log/stream",
    headers: {
      "x-admin-key": adminKey,
    },
  });

  assert.equal(response.status, 409);
  const payload = await response.json();
  assert.equal(payload?.error?.code, "LOGGING_DISABLED");
});

test("Runtime worker does not expose admin routes", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { adminKey } = await bootstrapKeys(env);
  const response = await callSpecificWorker(runtimeWorker, env, {
    method: "GET",
    path: "/_apiproxy/admin/version",
    headers: {
      "x-admin-key": adminKey,
    },
  });
  assert.equal(response.status, 404);
});

test("Control worker does not expose /request", SERIAL, async () => {
  const env = createEnv({}, {
    config_json_v1: JSON.stringify(minimalValidConfigPatch()),
  });
  const { proxyKey } = await bootstrapKeys(env);
  const response = await callSpecificWorker(controlWorker, env, {
    method: "POST",
    path: "/_apiproxy/request",
    headers: {
      "content-type": "application/json",
      "x-proxy-key": proxyKey,
    },
    body: JSON.stringify({
      upstream: { method: "GET", url: "/json" },
    }),
  });
  assert.equal(response.status, 404);
});
