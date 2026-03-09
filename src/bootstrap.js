import {
  htmlPage,
  escapeHtml,
  renderOnboardingHeader,
  renderAdminLoginOptions,
  renderInitAdminLoginScript,
  renderSecretField,
  renderSecretFieldScript,
} from "./ui.js";

function createBootstrapApi({
  constants,
  ensureKvBinding,
  kvGetValue,
  kvPutValue,
  kvStore,
  loadConfigV1,
  generateSecret,
  HttpError,
}) {
  const {
    kvProxyKey,
    kvAdminKey,
    kvProxyPrimaryCreatedAt,
    kvAdminPrimaryCreatedAt,
    adminRoot,
    defaultDocsUrl,
  } = constants;

  function getDocsBaseUrl(env) {
    const raw = String(env?.DOCS_URL || defaultDocsUrl || "").trim();
    return (raw ? raw : defaultDocsUrl).replace(/#.*$/, "");
  }

  function getDocsSectionUrl(env, sectionAnchor) {
    const raw = String(env?.DOCS_URL || defaultDocsUrl || "").trim();
    const base = raw ? raw.replace(/#.*$/, "") : defaultDocsUrl;
    return `${base}#${sectionAnchor}`;
  }

  async function bootstrapMissingKeys(env) {
    ensureKvBinding(env);
    const [existingProxy, existingAdmin] = await Promise.all([kvGetValue(env, kvProxyKey), kvGetValue(env, kvAdminKey)]);
    let createdProxy = null;
    let createdAdmin = null;
    const writes = [];

    if (!existingProxy) {
      createdProxy = generateSecret();
      writes.push(kvPutValue(env, kvProxyKey, createdProxy), kvStore(env).put(kvProxyPrimaryCreatedAt, String(Date.now())));
    }
    if (!existingAdmin) {
      createdAdmin = generateSecret();
      writes.push(kvPutValue(env, kvAdminKey, createdAdmin), kvStore(env).put(kvAdminPrimaryCreatedAt, String(Date.now())));
    }
    if (writes.length > 0) await Promise.all(writes);

    return {
      createdProxy,
      createdAdmin,
      proxyExists: !!(existingProxy || createdProxy),
      adminExists: !!(existingAdmin || createdAdmin),
    };
  }

  async function handleInitPage(env, request) {
    ensureKvBinding(env);
    const { createdProxy, createdAdmin } = await bootstrapMissingKeys(env);
    const keyManagementDocsUrl = getDocsSectionUrl(env, "key-management");
    const docsUrl = getDocsBaseUrl(env);

    return new Response(
      htmlPage(
        "API Transform Proxy",
        `${renderOnboardingHeader()}
       <h2 style="margin:0 0 10px 0;">Get Started</h2>
       <h3 style="margin:0 0 10px 0;">Step 1 - Get your credentials</h3>
       <div role="alert" style="border:1px solid #fecaca;background:#fff1f2;color:#7f1d1d;border-radius:10px;padding:10px 12px;margin:0 0 12px 0;">
         <div style="font-weight:700;">Save these API keys now</div>
         <div style="font-size:13px;">This is the only time they will be visible. Store them securely before leaving this page.</div>
       </div>
       ${renderSecretField(
         "Admin API Secret (To administer this proxy)",
         createdAdmin || "••••••••••••••••••••••••••••••••",
         "admin-api-secret",
         createdAdmin
           ? "API Key (New). Copy to a safe place. This key cannot be viewed more than once."
           : `API Key (Previously Created). This key cannot be viewed. See <a href="${escapeHtml(
               keyManagementDocsUrl
             )}" target="_blank" rel="noopener noreferrer">Rotating keys</a> to generate new keys.`,
         !!createdAdmin
       )}
       ${renderSecretField(
         "Requestor API Secret (To call endpoints through this proxy)",
         createdProxy || "••••••••••••••••••••••••••••••••",
         "requestor-api-secret",
         createdProxy
           ? "API Key (New). Copy to a safe place. This key cannot be viewed more than once."
           : `API Key (Previously Created). This key cannot be viewed. See <a href="${escapeHtml(
               keyManagementDocsUrl
             )}" target="_blank" rel="noopener noreferrer">Rotating keys</a> to generate new keys.`,
         !!createdProxy
       )}
       <h2 style="margin:16px 0 10px 0;">Step 2 - View/Configure This Proxy</h2>
       ${renderAdminLoginOptions(docsUrl)}
       ${renderSecretFieldScript()}
       ${renderInitAdminLoginScript(adminRoot)}`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  async function handleStatusPage(env, request) {
    ensureKvBinding(env);
    const [proxyKey, adminKey, config] = await Promise.all([kvGetValue(env, kvProxyKey), kvGetValue(env, kvAdminKey), loadConfigV1(env)]);
    const proxyInitialized = !!proxyKey;
    const adminInitialized = !!adminKey;
    if (!proxyInitialized || !adminInitialized) {
      return handleInitPage(env, request);
    }
    const docsUrl = getDocsBaseUrl(env);
    const proxyName = String(config?.proxyName || "").trim();

    return new Response(
      htmlPage(
        "API Transform Proxy",
        `${renderOnboardingHeader(proxyName)}
       <h2 style="margin:0 0 10px 0;">Step 2 - View/Configure This Proxy</h2>
       ${renderAdminLoginOptions(docsUrl)}
       ${renderInitAdminLoginScript(adminRoot)}`
      ),
      { headers: { "content-type": "text/html; charset=utf-8" } }
    );
  }

  async function handleBootstrapPost(env) {
    const { createdProxy, createdAdmin } = await bootstrapMissingKeys(env);
    if (!createdProxy && !createdAdmin) {
      throw new HttpError(409, "ALREADY_INITIALIZED", "Proxy and admin keys already exist; existing keys are never returned.");
    }
    return new Response(
      JSON.stringify({
        ok: true,
        data: {
          description: "initialization key generation",
          proxy_key: createdProxy || null,
          admin_key: createdAdmin || null,
        },
      }),
      {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      }
    );
  }

  return {
    getDocsBaseUrl,
    getDocsSectionUrl,
    bootstrapMissingKeys,
    handleInitPage,
    handleStatusPage,
    handleBootstrapPost,
  };
}

export { createBootstrapApi };
