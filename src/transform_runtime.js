function createTransformRuntimeApi({ isPlainObject, normalizeHeaderName, defaultHeaderForwarding, internalAuthHeadersSet, loadJsonata }) {
  function getInboundHeaderFilteringPolicy(config) {
    const targetResponse = isPlainObject(config?.transform?.target_response) ? config.transform.target_response : null;
    const section = isPlainObject(targetResponse?.header_filtering)
      ? targetResponse.header_filtering
      : (isPlainObject(config?.header_forwarding) ? config.header_forwarding : defaultHeaderForwarding);
    const mode = section?.mode === "whitelist" ? "whitelist" : "blacklist";
    const names = Array.isArray(section?.names)
      ? section.names.map((n) => normalizeHeaderName(n)).filter(Boolean)
      : (Array.isArray(defaultHeaderForwarding?.names) ? defaultHeaderForwarding.names : []);
    return { mode, namesSet: new Set(names) };
  }

  function shouldForwardIncomingHeader(headerNameLower, policy) {
    if (!headerNameLower) return false;
    if (internalAuthHeadersSet?.has?.(headerNameLower)) return false;
    const mode = policy?.mode === "whitelist" ? "whitelist" : "blacklist";
    const names = policy?.namesSet instanceof Set ? policy.namesSet : new Set();
    return mode === "whitelist" ? names.has(headerNameLower) : !names.has(headerNameLower);
  }

  function matchesStatusToken(status, token) {
    const s = Number(status);
    if (!Number.isInteger(s)) return false;

    if (typeof token === "number") return s === token;
    if (typeof token !== "string") return false;

    const t = token.trim().toLowerCase();
    if (/^[1-5]xx$/.test(t)) {
      return String(s).startsWith(t[0]);
    }
    const n = Number(t);
    return Number.isInteger(n) && s === n;
  }

  function matchesStatusList(status, list) {
    if (!Array.isArray(list) || list.length === 0) return false;
    return list.some((token) => matchesStatusToken(status, token));
  }

  function headerMatchValue(actual, expectedPattern) {
    const actualText = String(actual || "");
    const expected = String(expectedPattern || "");
    if (!expected) return false;
    const a = actualText.toLowerCase();
    const e = expected.toLowerCase();
    if (e.startsWith("*") && e.endsWith("*") && e.length >= 3) {
      return a.includes(e.slice(1, -1));
    }
    return a === e;
  }

  function ruleMatches(rule, ctx) {
    if (!rule || !ctx) return { matched: false, reasons: ["invalid rule/context"] };
    const reasons = [];

    const hasStatusConstraint = Array.isArray(rule.match_status) && rule.match_status.length > 0;
    if (hasStatusConstraint) {
      const statusOk = rule.match_status.some((token) => matchesStatusToken(ctx.status, token));
      if (!statusOk) reasons.push("status");
    }

    if (rule.match_type && rule.match_type !== "any" && rule.match_type !== ctx.type) {
      reasons.push("type");
    }

    if (Array.isArray(rule.match_headers) && rule.match_headers.length > 0) {
      for (const headerRule of rule.match_headers) {
        const name = String(headerRule?.name || "").toLowerCase();
        if (!name) continue;
        const actual = ctx.headers[name] || "";
        if (!headerMatchValue(actual, headerRule?.value)) {
          reasons.push(`header:${name}`);
        }
      }
    }
    if (Array.isArray(rule.match_method) && rule.match_method.length > 0) {
      const ctxMethod = String(ctx.method || "").toUpperCase();
      if (!rule.match_method.includes(ctxMethod)) {
        reasons.push("method");
      }
    }
    if (Array.isArray(rule.match_path) && rule.match_path.length > 0) {
      const p = String(ctx.path || "");
      const matched = rule.match_path.some((pattern) => {
        const s = String(pattern || "");
        if (!s) return false;
        if (s.endsWith("*")) return p.startsWith(s.slice(0, -1));
        return p === s;
      });
      if (!matched) reasons.push("path");
    }

    return { matched: reasons.length === 0, reasons };
  }

  function selectTransformRule(section, ctx) {
    const rules = Array.isArray(section?.rules) ? section.rules : [];
    const trace = [];

    for (const rule of rules) {
      const result = ruleMatches(rule, ctx);
      trace.push({ rule: rule.name, matched: result.matched, reasons: result.reasons });
      if (result.matched) {
        return { matchedRule: rule, trace };
      }
    }
    return { matchedRule: null, trace };
  }

  function matchesContentType(contentType, patterns) {
    const ct = String(contentType || "").toLowerCase();
    for (const p of patterns) {
      const pat = String(p || "").toLowerCase();
      if (!pat) continue;
      if (pat === "*") return true;
      if (pat.endsWith("*") && ct.startsWith(pat.slice(0, -1))) return true;
      if (ct.includes(pat)) return true;
    }
    return false;
  }

  function shouldRunTransform(when, status, contentType, responseBytes) {
    if (!isPlainObject(when)) return true;

    if (isPlainObject(when.status)) {
      if (Array.isArray(when.status.deny) && matchesStatusList(status, when.status.deny)) return false;
      if (Array.isArray(when.status.allow) && !matchesStatusList(status, when.status.allow)) return false;
    }

    if (isPlainObject(when.content_type)) {
      if (Array.isArray(when.content_type.deny) && matchesContentType(contentType, when.content_type.deny)) {
        return false;
      }
      if (Array.isArray(when.content_type.allow) && !matchesContentType(contentType, when.content_type.allow)) {
        return false;
      }
    }

    if (typeof when.max_response_bytes === "number" && responseBytes > when.max_response_bytes) {
      return false;
    }

    return true;
  }

  async function evalJsonataWithTimeout(exprString, inputObj, timeoutMs) {
    const jsonata = await loadJsonata();
    const expr = jsonata(exprString);

    const task = Promise.resolve(expr.evaluate(inputObj));
    const timeout = new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`JSONata timeout after ${timeoutMs}ms`)), timeoutMs);
    });

    return Promise.race([task, timeout]);
  }

  return {
    getInboundHeaderFilteringPolicy,
    shouldForwardIncomingHeader,
    selectTransformRule,
    shouldRunTransform,
    evalJsonataWithTimeout,
  };
}

export { createTransformRuntimeApi };
