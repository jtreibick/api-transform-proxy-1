function createProxyRuntimeApi(deps) {
  const {
    requireProxyKey,
    enforceInvokeContentType,
    readJsonWithLimit,
    getEnvInt,
    defaults,
    validateInvokePayload,
    HttpError,
    expectedRequestSchema,
    truncateJsonSnippet,
    loadConfigV1,
    defaultConfigV1,
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
    internalAuthHeaders,
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
    buildHttpRequestInit,
  } = deps;

  async function handleRootProxyRequest(request, env, ctx) {
    await requireProxyKey(request, env);
    const search = new URL(request.url).search || "";
    const payload = {
      upstream: {
        method: "GET",
        url: `/${search}`,
      },
    };
    return handleRequestCore(request, env, payload, ctx);
  }

  async function handleRequest(request, env, ctx) {
    await requireProxyKey(request, env);
    enforceInvokeContentType(request);

    const maxReq = getEnvInt(env, "MAX_REQ_BYTES", defaults.MAX_REQ_BYTES);
    const payload = await readJsonWithLimit(request, maxReq);
    const problems = validateInvokePayload(payload, { allowMissingUrl: true });
    if (problems.length > 0) {
      throw new HttpError(400, "INVALID_REQUEST", "Invalid /request payload", {
        expected: expectedRequestSchema,
        problems,
        received: truncateJsonSnippet(payload),
      });
    }
    return handleRequestCore(request, env, payload, ctx);
  }

  async function handleRequestCore(request, env, payload, ctx) {
    const maxResp = getEnvInt(env, "MAX_RESP_BYTES", defaults.MAX_RESP_BYTES);
    const maxExpr = getEnvInt(env, "MAX_EXPR_BYTES", defaults.MAX_EXPR_BYTES);
    const transformTimeoutMs = getEnvInt(env, "TRANSFORM_TIMEOUT_MS", defaults.TRANSFORM_TIMEOUT_MS);

    const config = await loadConfigV1(env);
    const outboundProxyRequestModel = isPlainObject(config?.http_requests?.outbound_proxy) ? config.http_requests.outbound_proxy : null;
    const jwtConfig = config?.jwt || defaultConfigV1.jwt;
    const transformGlobalEnabled = config?.transform?.enabled !== false;
    const sourceRequestTransformConfig = config?.transform?.source_request || defaultConfigV1.transform.source_request;
    const targetResponseTransformConfig = config?.transform?.target_response || defaultConfigV1.transform.target_response;
    const redactHeaderSet = getDebugRedactHeaderSet(config);
    const debugRequested = String(request.headers.get("X-Proxy-Debug") || "").trim() === "1";
    const debugActive = debugRequested ? await isDebugEnabled(env) : false;
    const debugTrace = debugActive
      ? {
          id: generateSecret().slice(0, 16),
          inbound: {
            timestamp: fmtTs(),
            method: request.method,
            path: new URL(request.url).pathname + new URL(request.url).search,
            headers: toRedactedHeaderMap(request.headers, redactHeaderSet),
            body_preview: previewBodyForDebug(payload),
          },
          outbound: null,
          target_response: null,
          transform: null,
          final_response: null,
        }
      : null;
    const proxyHost = resolveProxyHostForRequest(config);
    const headerForwardingPolicy = getInboundHeaderFilteringPolicy(config);

    if (jwtConfig?.enabled && jwtConfig?.inbound?.enabled) {
      const token = extractJwtFromHeaders(request.headers, jwtConfig.inbound);
      if (jwtConfig.inbound.mode === "jwks") {
        await verifyJwtRs256(token, jwtConfig.inbound, config, env);
      } else {
        const issuerState = await getIssuerKeyState(env);
        let verified = false;
        try {
          await verifyJwtHs256(token, issuerState.current, jwtConfig.inbound);
          verified = true;
        } catch (e) {
          const now = Date.now();
          const hasOld = issuerState.old && issuerState.oldExpiresAt && issuerState.oldExpiresAt > now;
          if (hasOld) {
            await verifyJwtHs256(token, issuerState.old, jwtConfig.inbound);
            verified = true;
          } else {
            throw e;
          }
        }
        if (!verified) {
          throw new HttpError(401, "JWT_INVALID", "JWT signature invalid");
        }
      }
    }

    if (transformGlobalEnabled && sourceRequestTransformConfig.enabled) {
      const outboundHook = resolveCustomHook(sourceRequestTransformConfig.custom_js_preprocessor);
      if (outboundHook) {
        let hookOutput;
        try {
          hookOutput = await outboundHook({
            upstream: payload.upstream,
            request_headers: normalizeHeaderMap(request.headers),
          });
        } catch (e) {
          throw new HttpError(422, "TRANSFORM_ERROR", "Outbound custom_js_preprocessor failed", {
            cause: String(e?.message || e),
          });
        }
        let nextUpstream = null;
        if (isPlainObject(hookOutput?.upstream)) {
          nextUpstream = hookOutput.upstream;
        } else if (isPlainObject(hookOutput)) {
          nextUpstream = hookOutput;
        }
        if (!nextUpstream) {
          throw new HttpError(422, "TRANSFORM_ERROR", "Outbound custom_js_preprocessor must return an object", {
            source: "custom_js_preprocessor",
          });
        }
        const nextPayload = { ...payload, upstream: nextUpstream };
        const outboundProblems = validateInvokePayload(nextPayload, { allowMissingUrl: true });
        if (outboundProblems.length > 0) {
          throw new HttpError(422, "TRANSFORM_ERROR", "Outbound custom_js_preprocessor returned invalid request payload", {
            problems: outboundProblems,
          });
        }
        payload = nextPayload;
      }
      const outboundCtx = {
        method: String(payload?.upstream?.method || "").toUpperCase(),
        path: String(payload?.upstream?.url || ""),
        headers: normalizeHeaderMap(payload?.upstream?.headers || {}),
      };
      const { matchedRule, trace } = selectTransformRule(sourceRequestTransformConfig, outboundCtx);
      let outboundExpr = "";
      let outboundSource = "none";
      if (matchedRule) {
        outboundExpr = matchedRule.expr || "";
        outboundSource = `rule:${matchedRule.name}`;
      } else if (sourceRequestTransformConfig.fallback === "transform_default" && sourceRequestTransformConfig.defaultExpr) {
        outboundExpr = sourceRequestTransformConfig.defaultExpr;
        outboundSource = "defaultExpr";
      } else if (sourceRequestTransformConfig.fallback === "error") {
        throw new HttpError(422, "TRANSFORM_RULE_NOT_MATCHED", "No outbound transform rule matched and fallback is set to error", {
          trace,
        });
      }
      if (outboundExpr) {
        const exprBytes = new TextEncoder().encode(outboundExpr).byteLength;
        if (exprBytes > maxExpr) {
          throw new HttpError(413, "EXPR_TOO_LARGE", `outbound transform expression exceeds ${maxExpr} bytes`);
        }
        let outboundOutput;
        try {
          outboundOutput = await evalJsonataWithTimeout(
            outboundExpr,
            {
              upstream: payload.upstream,
              request_headers: normalizeHeaderMap(request.headers),
            },
            transformTimeoutMs
          );
        } catch (e) {
          throw new HttpError(422, "TRANSFORM_ERROR", "Outbound JSONata evaluation failed", {
            cause: String(e?.message || e),
            source: outboundSource,
          });
        }
        let nextUpstream = null;
        if (isPlainObject(outboundOutput?.upstream)) {
          nextUpstream = outboundOutput.upstream;
        } else if (isPlainObject(outboundOutput)) {
          nextUpstream = outboundOutput;
        } else {
          throw new HttpError(422, "TRANSFORM_ERROR", "Outbound transform must return an object", {
            source: outboundSource,
          });
        }
        const nextPayload = { ...payload, upstream: nextUpstream };
        const outboundProblems = validateInvokePayload(nextPayload, { allowMissingUrl: true });
        if (outboundProblems.length > 0) {
          throw new HttpError(422, "TRANSFORM_ERROR", "Outbound transform produced an invalid request payload", {
            problems: outboundProblems,
          });
        }
        payload = nextPayload;
      }
    }

    let upstreamUrl;
    try {
      upstreamUrl = resolveUpstreamUrl(payload.upstream.url, proxyHost);
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(400, "INVALID_REQUEST", "upstream.url must be a valid URL", {
        expected: expectedRequestSchema,
        problems: ["upstream.url is not a valid URL"],
        received: truncateJsonSnippet(payload),
      });
    }

    const method = payload.upstream.method.toUpperCase();
    const allowedHosts = getAllowedHosts(env);
    assertSafeUpstreamUrl(upstreamUrl, allowedHosts);
    const outboundProxyInit = outboundProxyRequestModel
      ? await buildHttpRequestInit({ ...outboundProxyRequestModel, method }, config, env)
      : null;

    const upstreamHeaders = new Headers();

    for (const [k, v] of request.headers.entries()) {
      const lk = k.toLowerCase();
      if (!shouldForwardIncomingHeader(lk, headerForwardingPolicy)) continue;
      upstreamHeaders.set(k, v);
    }

    if (isPlainObject(payload.upstream.headers)) {
      for (const [k, v] of Object.entries(payload.upstream.headers)) {
        if (!k) continue;
        const lk = k.toLowerCase();
        if (internalAuthHeaders.has(lk)) continue;
        upstreamHeaders.set(k, String(v));
      }
    }

    const enrichedHeaders = await loadEnrichedHeadersMap(env);
    for (const [name, value] of Object.entries(enrichedHeaders)) {
      upstreamHeaders.set(name, value);
    }
    // Apply configured outbound proxy request/auth headers using same mechanics as other outbound calls.
    if (outboundProxyInit?.headers) {
      for (const [name, value] of outboundProxyInit.headers.entries()) {
        upstreamHeaders.set(name, value);
      }
    }

    const upstreamAuthProfile = String(payload?.upstream?.auth_profile || "").trim();
    if (upstreamAuthProfile) {
      const profiles = isNonArrayObject(config?.http_auth?.profiles) ? config.http_auth.profiles : {};
      if (!profiles?.[upstreamAuthProfile]) {
        throw new HttpError(400, "INVALID_REQUEST", "upstream.auth_profile must reference a defined http_auth profile", {
          expected: "Define http_auth.profiles.<name> in config YAML",
        });
      }
      const authHeaders = await resolveAuthProfileHeaders(upstreamAuthProfile, config, env);
      for (const [name, value] of Object.entries(authHeaders)) {
        upstreamHeaders.set(name, value);
      }
    }

    if (jwtConfig?.enabled && jwtConfig?.outbound?.enabled) {
      const issuerState = await getIssuerKeyState(env);
      const nowSec = Math.floor(Date.now() / 1000);
      const ttl = Number.isInteger(jwtConfig.outbound.ttl_seconds) ? jwtConfig.outbound.ttl_seconds : 3600;
      const payload = {
        iat: nowSec,
        exp: nowSec + ttl,
      };
      if (jwtConfig.outbound.issuer) payload.iss = jwtConfig.outbound.issuer;
      if (jwtConfig.outbound.audience) payload.aud = jwtConfig.outbound.audience;
      if (jwtConfig.outbound.subject) payload.sub = jwtConfig.outbound.subject;
      const token = await signJwtHs256(payload, issuerState.current);
      const headerName = jwtConfig.outbound.header || "Authorization";
      const scheme = jwtConfig.outbound.scheme === null ? "" : String(jwtConfig.outbound.scheme || "Bearer").trim();
      const value = scheme ? `${scheme} ${token}` : token;
      upstreamHeaders.set(headerName, value);
    }

    let upstreamBody;
    if (method !== "GET" && method !== "HEAD") {
      const body = isPlainObject(payload.upstream.body) ? payload.upstream.body : { type: "none" };
      const bodyType = String(body.type || "none").toLowerCase();

      if (bodyType === "json") {
        upstreamHeaders.set("Content-Type", "application/json");
        upstreamBody = JSON.stringify(body.value ?? {});
      } else if (bodyType === "urlencoded") {
        upstreamHeaders.set("Content-Type", "application/x-www-form-urlencoded");
        if (typeof body.raw === "string") {
          upstreamBody = body.raw;
        } else {
          const params = new URLSearchParams();
          const source = isPlainObject(body.value) ? body.value : {};
          for (const [k, v] of Object.entries(source)) params.append(k, String(v));
          upstreamBody = params.toString();
        }
      } else if (bodyType === "raw") {
        if (typeof body.content_type === "string" && body.content_type) {
          upstreamHeaders.set("Content-Type", body.content_type);
        }
        upstreamBody = typeof body.raw === "string" ? body.raw : "";
      }
      if (upstreamBody === undefined && outboundProxyInit && outboundProxyInit.body !== undefined) {
        upstreamBody = outboundProxyInit.body;
      }
    }

    if (debugTrace) {
      debugTrace.outbound = {
        timestamp: fmtTs(),
        url: upstreamUrl.toString(),
        method,
        headers: toRedactedHeaderMap(upstreamHeaders, redactHeaderSet),
        body_preview: previewBodyForDebug(upstreamBody || ""),
      };
    }

    const t0 = Date.now();
    let upstreamResp;
    try {
      upstreamResp = await fetch(upstreamUrl.toString(), {
        method,
        headers: upstreamHeaders,
        body: upstreamBody,
        redirect: "manual",
      });
    } catch (e) {
      throw new HttpError(502, "UPSTREAM_FETCH_FAILED", "Failed to fetch upstream", {
        cause: String(e?.message || e),
      });
    }
    const upstreamMs = Date.now() - t0;

    const responseBytes = await readResponseWithLimit(upstreamResp, maxResp);
    let contentType = getStoredContentType(upstreamResp.headers);
    let textBody = decodeBody(responseBytes);
    let responseHeadersMap = normalizeHeaderMap(upstreamResp.headers);
    let responseStatus = upstreamResp.status;
    let jsonBody = null;
    let parseMs;
    let responseType = detectResponseType(contentType);
    if (responseType === "json") {
      const parseStart = Date.now();
      jsonBody = parseJsonOrNull(textBody);
      parseMs = Date.now() - parseStart;
    }
    if (debugTrace) {
      debugTrace.target_response = {
        timestamp: fmtTs(),
        status: upstreamResp.status,
        headers: toRedactedHeaderMap(upstreamResp.headers, redactHeaderSet),
        body_preview: previewBodyForDebug(responseType === "json" ? jsonBody ?? textBody : textBody),
      };
    }

    if (transformGlobalEnabled && targetResponseTransformConfig.enabled) {
      const inboundHook = resolveCustomHook(targetResponseTransformConfig.custom_js_preprocessor);
      if (inboundHook) {
        let hookOutput;
        try {
          hookOutput = await inboundHook({
            status: responseStatus,
            headers: responseHeadersMap,
            type: responseType,
            content_type: contentType || null,
            body: responseType === "json" ? jsonBody : textBody,
          });
        } catch (e) {
          throw new HttpError(422, "TRANSFORM_ERROR", "Inbound custom_js_preprocessor failed", {
            cause: String(e?.message || e),
          });
        }
        if (!isPlainObject(hookOutput)) {
          throw new HttpError(422, "TRANSFORM_ERROR", "Inbound custom_js_preprocessor must return an object", {
            source: "custom_js_preprocessor",
          });
        }
        if (hookOutput.status !== undefined) {
          const nextStatus = Number(hookOutput.status);
          if (Number.isFinite(nextStatus)) responseStatus = nextStatus;
        }
        if (hookOutput.headers && isPlainObject(hookOutput.headers)) {
          responseHeadersMap = normalizeHeaderMap(hookOutput.headers);
        }
        if (hookOutput.content_type !== undefined) {
          contentType = hookOutput.content_type === null ? null : String(hookOutput.content_type || "").trim() || null;
        }
        if (hookOutput.type && deps.validTransformTypes.has(String(hookOutput.type).toLowerCase())) {
          responseType = String(hookOutput.type).toLowerCase();
        }
        if (hookOutput.body !== undefined) {
          if (responseType === "json") {
            if (typeof hookOutput.body === "string") {
              jsonBody = parseJsonOrNull(hookOutput.body);
            } else {
              jsonBody = hookOutput.body;
            }
          } else {
            textBody = typeof hookOutput.body === "string" ? hookOutput.body : JSON.stringify(hookOutput.body);
          }
        }
      }
    }

    async function emitDebugTrace(transformInfo, finalHttpStatus, finalBody) {
      return observabilityApi.recordDebugTraceAndSink({
        debugTrace,
        transformInfo,
        finalHttpStatus,
        finalBody,
        config,
        env,
      });
    }

    const metaBase = {
      status: responseStatus,
      upstream_ms: upstreamMs,
      upstream_headers: toSafeUpstreamHeaders(upstreamResp.headers),
      content_type: contentType || null,
      response_bytes: responseBytes.byteLength,
    };

    if (!transformGlobalEnabled || !targetResponseTransformConfig.enabled) {
      if (responseType === "json" && jsonBody === null) {
        const debugHeaders = await emitDebugTrace(
          {
            action: "error",
            matched_rule: null,
            expression_source: "none",
            output_preview: "INVALID_JSON_RESPONSE",
          },
          200,
          { error: { code: "INVALID_JSON_RESPONSE" } }
        );
        return jsonResponse(
          200,
          errorEnvelope("INVALID_JSON_RESPONSE", "Upstream indicated JSON but body could not be parsed", null, metaBase),
          debugHeaders
        );
      }
      const passthroughData = jsonBody !== null ? jsonBody : textBody;
      const debugHeaders = await emitDebugTrace(
        {
          action: "skipped",
          matched_rule: null,
          expression_source: "none",
          output_preview: passthroughData,
        },
        200,
        successEnvelope(passthroughData, metaBase)
      );
      return jsonResponse(200, successEnvelope(passthroughData, metaBase), debugHeaders);
    }

    const ruleCtx = {
      status: responseStatus,
      type: responseType,
      headers: responseHeadersMap,
    };
    const { matchedRule, trace } = selectTransformRule(targetResponseTransformConfig, ruleCtx);

    let expr = "";
    let transformSource = "none";
    if (matchedRule) {
      expr = matchedRule.expr || "";
      transformSource = `rule:${matchedRule.name}`;
    } else if (targetResponseTransformConfig.fallback === "transform_default" && targetResponseTransformConfig.defaultExpr) {
      expr = targetResponseTransformConfig.defaultExpr;
      transformSource = "defaultExpr";
    } else if (targetResponseTransformConfig.fallback === "passthrough") {
      if (responseType === "json" && jsonBody === null) {
        const debugHeaders = await emitDebugTrace(
          {
            action: "error",
            matched_rule: null,
            expression_source: "none",
            output_preview: "INVALID_JSON_RESPONSE",
          },
          200,
          { error: { code: "INVALID_JSON_RESPONSE" } }
        );
        return jsonResponse(
          200,
          errorEnvelope("INVALID_JSON_RESPONSE", "Upstream indicated JSON but body could not be parsed", null, metaBase),
          debugHeaders
        );
      }
      const passthroughData = jsonBody !== null ? jsonBody : textBody;
      const passthroughEnvelope = successEnvelope(passthroughData, {
        ...metaBase,
        skipped: true,
        transform_trace: trace,
      });
      const debugHeaders = await emitDebugTrace(
        {
          action: "skipped",
          matched_rule: null,
          expression_source: "none",
          output_preview: passthroughData,
        },
        200,
        passthroughEnvelope
      );
      return jsonResponse(200, passthroughEnvelope, debugHeaders);
    } else {
      throw new HttpError(422, "TRANSFORM_RULE_NOT_MATCHED", "No transform rule matched and fallback is set to error", {
        status: responseStatus,
        type: responseType,
        trace,
      });
    }

    const exprBytes = new TextEncoder().encode(expr).byteLength;
    if (exprBytes > maxExpr) {
      throw new HttpError(413, "EXPR_TOO_LARGE", `transform expression exceeds ${maxExpr} bytes`);
    }

    if (responseType === "json" && jsonBody === null) {
      throw new HttpError(422, "NON_JSON_RESPONSE", "Transform selected but upstream JSON could not be parsed", {
        content_type: contentType || null,
      });
    }

    const transformStart = Date.now();
    let output;
    try {
      output = await evalJsonataWithTimeout(
        expr,
        {
          status: responseStatus,
          headers: responseHeadersMap,
          type: responseType,
          content_type: contentType || null,
          body: responseType === "json" ? jsonBody : textBody,
        },
        transformTimeoutMs
      );
    } catch (e) {
      throw new HttpError(422, "TRANSFORM_ERROR", "JSONata evaluation failed", {
        cause: String(e?.message || e),
        source: transformSource,
      });
    }
    const transformMs = Date.now() - transformStart;
    const finalEnvelope = successEnvelope(output, {
      ...metaBase,
      parse_ms: parseMs,
      transform_ms: transformMs,
      transform_source: transformSource,
      transform_trace: trace,
    });
    const debugHeaders = await emitDebugTrace(
      {
        action: "executed",
        matched_rule: matchedRule ? matchedRule.name : null,
        expression_source: transformSource,
        output_preview: output,
      },
      200,
      finalEnvelope
    );
    return jsonResponse(200, finalEnvelope, debugHeaders);
  }

  return {
    handleRootProxyRequest,
    handleRequest,
    handleRequestCore,
  };
}

export { createProxyRuntimeApi };
