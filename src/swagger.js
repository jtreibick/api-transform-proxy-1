function createSwaggerApi({ htmlPage, reservedRoot, adminRoot }) {
  function buildOpenApiSpec(request) {
    const url = new URL(request.url);
    const serverUrl = `${url.protocol}//${url.host}`;
    const jsonBody = {
      content: {
        "application/json": {
          schema: { type: "object", additionalProperties: true },
        },
      },
    };

    return {
      openapi: "3.0.3",
      info: {
        title: "API Transform Proxy",
        version: "1.0.0",
        description: "Cloudflare Worker relay + transform proxy API.",
      },
      servers: [{ url: serverUrl }],
      components: {
        securitySchemes: {
          ProxyKeyHeader: { type: "apiKey", in: "header", name: "X-Proxy-Key" },
          AdminKeyHeader: { type: "apiKey", in: "header", name: "X-Admin-Key" },
          IssuerKeyHeader: { type: "apiKey", in: "header", name: "X-Issuer-Key" },
          AdminBearer: { type: "http", scheme: "bearer" },
        },
        schemas: {
          AnyObject: { type: "object", additionalProperties: true },
        },
      },
      paths: {
        [reservedRoot]: {
          get: {
            summary: "Bootstrap/status page",
            responses: { "200": { description: "HTML status page" } },
          },
          post: {
            summary: "Bootstrap keys (returns newly created keys only)",
            security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }],
            requestBody: jsonBody,
            responses: { "200": { description: "Bootstrap result" } },
          },
        },
        [`${reservedRoot}/request`]: {
          post: {
            summary: "Relay request to upstream target",
            security: [{ ProxyKeyHeader: [] }],
            requestBody: jsonBody,
            responses: { "200": { description: "Relay envelope response" } },
          },
        },
        [`${reservedRoot}/jwt`]: {
          post: {
            summary: "Issue JWT from proxy",
            security: [{ IssuerKeyHeader: [] }],
            requestBody: jsonBody,
            responses: { "200": { description: "JWT issue response" } },
          },
        },
        [`${reservedRoot}/keys/proxy/rotate`]: {
          post: { summary: "Rotate proxy key (self)", security: [{ ProxyKeyHeader: [] }], responses: { "200": { description: "New key" } } },
        },
        [`${reservedRoot}/keys/issuer/rotate`]: {
          post: { summary: "Rotate issuer key (self)", security: [{ IssuerKeyHeader: [] }], responses: { "200": { description: "New key" } } },
        },
        [`${reservedRoot}/keys/admin/rotate`]: {
          post: { summary: "Rotate admin key", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "New key" } } },
        },
        [`${adminRoot}/access-token`]: {
          post: {
            summary: "Create short-lived admin access token",
            security: [{ AdminKeyHeader: [] }],
            responses: { "200": { description: "Access token response" } },
          },
        },
        [`${adminRoot}/version`]: {
          get: { summary: "Get version info", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Version" } } },
        },
        [`${adminRoot}/keys`]: {
          get: { summary: "Get key status", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Key status" } } },
        },
        [`${adminRoot}/keys/proxy/rotate`]: {
          post: { summary: "Rotate proxy key (admin)", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "New key" } } },
        },
        [`${adminRoot}/keys/issuer/rotate`]: {
          post: { summary: "Rotate issuer key (admin)", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "New key" } } },
        },
        [`${adminRoot}/keys/admin/rotate`]: {
          post: { summary: "Rotate admin key (admin)", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "New key" } } },
        },
        [`${adminRoot}/config`]: {
          get: { summary: "Get YAML config", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "YAML config text" } } },
          put: {
            summary: "Save config (YAML or JSON)",
            security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }],
            requestBody: {
              content: {
                "text/yaml": { schema: { type: "string" } },
                "application/json": { schema: { type: "object", additionalProperties: true } },
              },
            },
            responses: { "200": { description: "Updated config" } },
          },
        },
        [`${adminRoot}/config/validate`]: {
          post: {
            summary: "Validate config (YAML or JSON)",
            security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }],
            requestBody: {
              content: {
                "text/yaml": { schema: { type: "string" } },
                "application/json": { schema: { type: "object", additionalProperties: true } },
              },
            },
            responses: { "200": { description: "Validation result" } },
          },
        },
        [`${adminRoot}/config/test-rule`]: {
          post: { summary: "Test transform rule matcher", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], requestBody: jsonBody, responses: { "200": { description: "Rule test output" } } },
        },
        [`${adminRoot}/key-rotation-config`]: {
          get: { summary: "Get outbound auth/rotation config", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Rotation config" } } },
          put: { summary: "Set outbound auth/rotation config", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], requestBody: jsonBody, responses: { "200": { description: "Updated" } } },
        },
        [`${adminRoot}/transform-config`]: {
          get: { summary: "Get transform config", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Transform config" } } },
          put: { summary: "Set transform config", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], requestBody: jsonBody, responses: { "200": { description: "Updated" } } },
        },
        [`${adminRoot}/debug`]: {
          get: { summary: "Get logging/debug status", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Status" } } },
          put: { summary: "Enable logging/debug", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], requestBody: jsonBody, responses: { "200": { description: "Enabled" } } },
          delete: { summary: "Disable logging/debug", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Disabled" } } },
        },
        [`${adminRoot}/debug/last`]: {
          get: { summary: "Get last debug trace", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Trace text/json/html" } } },
        },
        [`${adminRoot}/live-log/stream`]: {
          get: {
            summary: "Live debug stream (SSE)",
            security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }],
            responses: { "200": { description: "text/event-stream" }, "409": { description: "LOGGING_DISABLED" } },
          },
        },
        [`${adminRoot}/debug/loggingSecret`]: {
          get: { summary: "Get logging secret set status", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Status" } } },
          put: { summary: "Set logging secret", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], requestBody: jsonBody, responses: { "200": { description: "Saved" } } },
          delete: { summary: "Delete logging secret", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Deleted" } } },
        },
        [`${adminRoot}/http-auth/{profile}/secret`]: {
          parameters: [{ name: "profile", in: "path", required: true, schema: { type: "string" } }],
          get: { summary: "Get http_auth profile secret set status", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Status" } } },
          put: { summary: "Set http_auth profile secret", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], requestBody: jsonBody, responses: { "200": { description: "Saved" } } },
          delete: { summary: "Delete http_auth profile secrets", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Deleted" } } },
        },
        [`${adminRoot}/http-secrets/{ref}`]: {
          parameters: [{ name: "ref", in: "path", required: true, schema: { type: "string" } }],
          get: { summary: "Get HTTP secret set status", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Status" } } },
          put: { summary: "Set HTTP secret value", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], requestBody: jsonBody, responses: { "200": { description: "Saved" } } },
          delete: { summary: "Delete HTTP secret", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Deleted" } } },
        },
        [`${adminRoot}/headers`]: {
          get: { summary: "List enrichments", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Header names" } } },
        },
        [`${adminRoot}/headers/{headerName}`]: {
          parameters: [{ name: "headerName", in: "path", required: true, schema: { type: "string" } }],
          put: { summary: "Set enrichment header", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], requestBody: jsonBody, responses: { "200": { description: "Saved" } } },
          delete: { summary: "Delete enrichment header", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "Deleted" } } },
        },
        [`${adminRoot}/swagger/openapi.json`]: {
          get: { summary: "OpenAPI spec JSON", security: [{ AdminKeyHeader: [] }, { AdminBearer: [] }], responses: { "200": { description: "OpenAPI JSON" } } },
        },
      },
    };
  }

  function handleAdminSwaggerSpec(request) {
    return new Response(JSON.stringify(buildOpenApiSpec(request), null, 2), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  function handleAdminSwaggerPage(request) {
    const specJson = JSON.stringify(buildOpenApiSpec(request)).replace(/</g, "\\u003c");
    const body = `
    <div style="padding:12px 0 14px 0;">
      <p style="margin:0;color:#475569;">Admin-protected Swagger documentation</p>
    </div>
    <div id="swagger-ui"></div>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      const __SPEC__ = ${specJson};
      window.ui = SwaggerUIBundle({
        spec: __SPEC__,
        dom_id: '#swagger-ui',
        deepLinking: true,
        displayRequestDuration: true,
        tryItOutEnabled: true,
      });
    </script>
  `;

    return new Response(htmlPage("Admin Swagger", body), {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  return {
    buildOpenApiSpec,
    handleAdminSwaggerSpec,
    handleAdminSwaggerPage,
  };
}

export { createSwaggerApi };
