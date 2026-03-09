import { HttpError } from "./lib.js";

function createObservabilityApi({
  adminRoot,
  kvDebugEnabledUntilMsKey,
  builtinDebugRedactHeaders,
  debugMaxTraceChars,
  debugMaxBodyPreviewChars,
  ensureKvBinding,
  kvStore,
  normalizeHeaderMap,
  loadConfigV1,
  getEnvInt,
  defaults,
  enforceInvokeContentType,
  readJsonWithLimit,
  jsonResponse,
  htmlPage,
  escapeHtml,
  buildHttpRequestInit,
}) {
  let lastDebugTrace = null;
  const liveLogClients = new Set();

  async function readDebugEnabledUntilMs(env) {
    ensureKvBinding(env);
    const raw = await kvStore(env).get(kvDebugEnabledUntilMsKey);
    const value = Number(raw);
    return Number.isFinite(value) ? value : 0;
  }

  async function isDebugEnabled(env) {
    const until = await readDebugEnabledUntilMs(env);
    return until > Date.now();
  }

  function redactDebugValue(value) {
    let text = String(value ?? "");
    text = text.replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, "Bearer ***REDACTED***");
    text = text.replace(/(\"(?:token|secret|password|api[_-]?key|authorization)\"\s*:\s*\")([^\"]+)(\")/gi, "$1***REDACTED***$3");
    return text;
  }

  function getDebugRedactHeaderSet() {
    return new Set(builtinDebugRedactHeaders);
  }

  function toRedactedHeaderMap(headersLike, redactedHeadersSet = null) {
    const sensitive = redactedHeadersSet || new Set([
      "authorization",
      "proxy-authorization",
      "cookie",
      "set-cookie",
      "x-proxy-key",
      "x-admin-key",
    ]);
    const map = normalizeHeaderMap(headersLike);
    const out = {};
    for (const [k, v] of Object.entries(map)) {
      const lk = k.toLowerCase();
      const maybeSensitive = sensitive.has(lk) || lk.includes("token") || lk.includes("secret") || lk.includes("key");
      out[lk] = maybeSensitive ? "***REDACTED***" : redactDebugValue(v);
    }
    return out;
  }

  function previewBodyForDebug(value) {
    let text = "";
    if (value === undefined || value === null) {
      text = "";
    } else if (typeof value === "string") {
      text = value;
    } else {
      try {
        text = JSON.stringify(value);
      } catch {
        text = String(value);
      }
    }
    text = redactDebugValue(text);
    if (text.length > debugMaxBodyPreviewChars) {
      return `${text.slice(0, debugMaxBodyPreviewChars)}...(truncated)`;
    }
    return text;
  }

  function fmtTs(date = new Date()) {
    return date.toISOString();
  }

  function sectionText(title, timestamp, lines) {
    const body = Array.isArray(lines) ? lines.filter(Boolean).join("\n") : String(lines || "");
    return `----- ${title} -----\nTimestamp: ${timestamp}\n${body}\n`;
  }

  function buildDebugTraceText(trace) {
    const parts = [
      sectionText("INBOUND REQUEST", trace.inbound.timestamp, [
        `Method: ${trace.inbound.method}`,
        `Path: ${trace.inbound.path}`,
        `Headers: ${JSON.stringify(trace.inbound.headers, null, 2)}`,
        `Body Preview: ${trace.inbound.body_preview}`,
      ]),
      sectionText("OUTBOUND REQUEST (to target)", trace.outbound.timestamp, [
        `URL: ${trace.outbound.url}`,
        `Method: ${trace.outbound.method}`,
        `Headers: ${JSON.stringify(trace.outbound.headers, null, 2)}`,
        `Body Preview: ${trace.outbound.body_preview}`,
      ]),
      sectionText("TARGET RESPONSE (native)", trace.target_response.timestamp, [
        `Status: ${trace.target_response.status}`,
        `Headers: ${JSON.stringify(trace.target_response.headers, null, 2)}`,
        `Body Preview: ${trace.target_response.body_preview}`,
      ]),
      sectionText("TRANSFORM", trace.transform.timestamp, [
        `Action: ${trace.transform.action}`,
        `Matched Rule: ${trace.transform.matched_rule || "none"}`,
        `Expression Source: ${trace.transform.expression_source || "none"}`,
        `Output Preview: ${trace.transform.output_preview}`,
      ]),
      sectionText("FINAL RESPONSE (to requester)", trace.final_response.timestamp, [
        `HTTP Status: ${trace.final_response.http_status}`,
        `Body Preview: ${trace.final_response.body_preview}`,
      ]),
    ];
    const text = parts.join("\n");
    return text.length > debugMaxTraceChars ? `${text.slice(0, debugMaxTraceChars)}\n...(truncated)` : text;
  }

  function encodeSseEvent(eventName, data) {
    const payload = typeof data === "string" ? data : JSON.stringify(data ?? {});
    const lines = String(payload)
      .split("\n")
      .map((line) => `data: ${line}`)
      .join("\n");
    return `event: ${eventName}\n${lines}\n\n`;
  }

  function broadcastLiveLogEvent(eventName, data) {
    if (!liveLogClients.size) return;
    const encoded = new TextEncoder().encode(encodeSseEvent(eventName, data));
    for (const client of [...liveLogClients]) {
      try {
        client.controller.enqueue(encoded);
      } catch {
        liveLogClients.delete(client);
        try {
          if (client.heartbeat) clearInterval(client.heartbeat);
        } catch {}
        try {
          client.controller.close();
        } catch {}
      }
    }
  }

  async function pushDebugTraceToLoggingUrl(traceText, traceData, config, env) {
    const sink = config?.debug?.loggingEndpoint || {};
    const req = typeof sink?.http_request === "object" && sink?.http_request !== null ? sink.http_request : null;
    const url = String(req?.url || "").trim();
    if (!url) return { attempted: false, ok: true };
    const init = await buildHttpRequestInit({ ...req, method: req?.method || "POST" }, config, env);
    const headers = new Headers(init.headers || {});
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
    try {
      const res = await fetch(url, {
        method: init.method || "POST",
        headers,
        body: JSON.stringify({
          trace_text: traceText,
          trace: traceData,
        }),
      });
      if (!res.ok) {
        return {
          attempted: true,
          ok: false,
          error_code: "SINK_HTTP_ERROR",
          status: res.status,
        };
      }
      return { attempted: true, ok: true };
    } catch {
      return {
        attempted: true,
        ok: false,
        error_code: "SINK_FETCH_FAILED",
      };
    }
  }

  async function recordDebugTraceAndSink({ debugTrace, transformInfo, finalHttpStatus, finalBody, config, env }) {
    if (!debugTrace) return null;
    debugTrace.transform = {
      timestamp: fmtTs(),
      action: transformInfo.action,
      matched_rule: transformInfo.matched_rule || null,
      expression_source: transformInfo.expression_source || "none",
      output_preview: previewBodyForDebug(transformInfo.output_preview || ""),
    };
    debugTrace.final_response = {
      timestamp: fmtTs(),
      http_status: finalHttpStatus,
      body_preview: previewBodyForDebug(finalBody),
    };
    const traceText = buildDebugTraceText(debugTrace);
    lastDebugTrace = {
      id: debugTrace.id,
      timestamp: fmtTs(),
      text: traceText,
    };
    broadcastLiveLogEvent("trace", lastDebugTrace);
    const sink = await pushDebugTraceToLoggingUrl(traceText, debugTrace, config, env);
    const loggingUrlStatus = !sink.attempted
      ? "off"
      : sink.ok
        ? "ok"
        : `error:${sink.error_code || "LOGGING_URL_ERROR"}${sink.status ? `:${sink.status}` : ""}`;
    return {
      "X-Proxy-Debug": "True",
      "X-Proxy-Debug-Trace-Id": debugTrace.id,
      "X-Proxy-Debug-Logging-Endpoint-Status": loggingUrlStatus,
    };
  }

  async function handleDebugLastGet(request) {
    const acceptsHtml = (request.headers.get("accept") || "").includes("text/html");
    if (!lastDebugTrace) {
      if (acceptsHtml) {
        return new Response(
          htmlPage("Last Debug Trace", "<p>No debug trace has been captured in this Worker instance yet.</p>"),
          { headers: { "content-type": "text/html; charset=utf-8" } }
        );
      }
      return jsonResponse(200, {
        ok: true,
        data: { available: false },
        meta: {},
      });
    }
    if (acceptsHtml) {
      return new Response(
        htmlPage(
          "Last Debug Trace",
          `<pre style="padding:12px;border:1px solid #ddd;border-radius:8px;white-space:pre-wrap;word-break:break-word;">${escapeHtml(
            lastDebugTrace.text
          )}</pre>`
        ),
        { headers: { "content-type": "text/html; charset=utf-8" } }
      );
    }
    return new Response(lastDebugTrace.text, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  async function handleLiveLogStream(env) {
    const enabled = await isDebugEnabled(env);
    if (!enabled) {
      throw new HttpError(409, "LOGGING_DISABLED", "Live log is unavailable because logging is disabled.", {
        hint: `Enable logging via PUT ${adminRoot}/debug before opening live log.`,
      });
    }
    const encoder = new TextEncoder();
    let clientRef = null;
    const stream = new ReadableStream({
      start(controller) {
        const heartbeat = setInterval(() => {
          try {
            controller.enqueue(encoder.encode(": ping\n\n"));
          } catch {}
        }, 15000);
        clientRef = { controller, heartbeat };
        liveLogClients.add(clientRef);
        controller.enqueue(encoder.encode(encodeSseEvent("connected", { timestamp: new Date().toISOString() })));
        if (lastDebugTrace?.text) {
          controller.enqueue(encoder.encode(encodeSseEvent("last_trace", lastDebugTrace)));
        }
      },
      cancel() {
        if (!clientRef) return;
        liveLogClients.delete(clientRef);
        try {
          if (clientRef.heartbeat) clearInterval(clientRef.heartbeat);
        } catch {}
        clientRef = null;
      },
    });
    return new Response(stream, {
      status: 200,
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
        "x-accel-buffering": "no",
      },
    });
  }

  async function handleDebugGet(env) {
    const config = await loadConfigV1(env);
    const maxTtlSeconds = Number(config?.debug?.max_debug_session_seconds || 3600);
    const enabledUntilMs = await readDebugEnabledUntilMs(env);
    const now = Date.now();
    return jsonResponse(200, {
      ok: true,
      data: {
        enabled: enabledUntilMs > now,
        enabled_until_ms: enabledUntilMs || 0,
        ttl_remaining_seconds: enabledUntilMs > now ? Math.ceil((enabledUntilMs - now) / 1000) : 0,
        max_debug_session_seconds: maxTtlSeconds,
      },
      meta: {},
    });
  }

  async function handleDebugPut(request, env) {
    enforceInvokeContentType(request);
    const body = await readJsonWithLimit(request, getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES));
    const enabled = body?.enabled;
    if (typeof enabled !== "boolean") {
      throw new HttpError(400, "INVALID_REQUEST", "enabled is required and must be a boolean", {
        expected: { enabled: true, ttl_seconds: 3600 },
      });
    }

    const config = await loadConfigV1(env);
    const maxTtlSeconds = Number(config?.debug?.max_debug_session_seconds || 3600);

    if (!enabled) {
      await kvStore(env).put(kvDebugEnabledUntilMsKey, "0");
      return jsonResponse(200, {
        ok: true,
        data: {
          enabled: false,
          enabled_until_ms: 0,
          ttl_remaining_seconds: 0,
          max_debug_session_seconds: maxTtlSeconds,
        },
        meta: {},
      });
    }

    const ttlSecondsRaw = body?.ttl_seconds === undefined ? maxTtlSeconds : Number(body.ttl_seconds);
    if (!Number.isInteger(ttlSecondsRaw) || ttlSecondsRaw < 1) {
      throw new HttpError(400, "INVALID_REQUEST", "ttl_seconds must be a positive integer", {
        expected: { enabled: true, ttl_seconds: 3600 },
      });
    }
    if (ttlSecondsRaw > maxTtlSeconds) {
      throw new HttpError(400, "INVALID_REQUEST", "ttl_seconds exceeds configured debug.max_debug_session_seconds", {
        received: ttlSecondsRaw,
        max_debug_session_seconds: maxTtlSeconds,
      });
    }

    const enabledUntilMs = Date.now() + ttlSecondsRaw * 1000;
    await kvStore(env).put(kvDebugEnabledUntilMsKey, String(enabledUntilMs));
    return jsonResponse(200, {
      ok: true,
      data: {
        enabled: true,
        enabled_until_ms: enabledUntilMs,
        ttl_remaining_seconds: ttlSecondsRaw,
        max_debug_session_seconds: maxTtlSeconds,
      },
      meta: {},
    });
  }

  async function handleDebugDelete(env) {
    await kvStore(env).put(kvDebugEnabledUntilMsKey, "0");
    const config = await loadConfigV1(env);
    const maxTtlSeconds = Number(config?.debug?.max_debug_session_seconds || 3600);
    return jsonResponse(200, {
      ok: true,
      data: {
        enabled: false,
        enabled_until_ms: 0,
        ttl_remaining_seconds: 0,
        max_debug_session_seconds: maxTtlSeconds,
      },
      meta: {},
    });
  }

  return {
    isDebugEnabled,
    getDebugRedactHeaderSet,
    toRedactedHeaderMap,
    previewBodyForDebug,
    fmtTs,
    handleDebugLastGet,
    handleLiveLogStream,
    handleDebugGet,
    handleDebugPut,
    handleDebugDelete,
    recordDebugTraceAndSink,
  };
}

export { createObservabilityApi };
