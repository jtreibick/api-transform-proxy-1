async function dispatchAdminRoute({ normalizedPath, request, env, adminRoot, handlers, auth }) {
  if (normalizedPath === adminRoot && request.method === "GET") {
    return handlers.handleAdminPage();
  }
  if (normalizedPath === `${adminRoot}/assets/admin-page.js` && request.method === "GET") {
    return handlers.handleAdminPageScriptAsset();
  }
  if (normalizedPath === `${adminRoot}/swagger` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleAdminSwaggerPage(request);
  }
  if (normalizedPath === `${adminRoot}/swagger/openapi.json` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleAdminSwaggerSpec(request);
  }
  if (normalizedPath === `${adminRoot}/access-token` && request.method === "POST") {
    await auth.requireAdminKey(request, env);
    return handlers.handleAdminAccessTokenPost(env);
  }
  if (normalizedPath === `${adminRoot}/version` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleVersion(env);
  }

  if (normalizedPath === `${adminRoot}/keys/proxy/rotate` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleRotateByKind("proxy", request, env);
  }
  if (normalizedPath === `${adminRoot}/keys/issuer/rotate` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleRotateByKind("issuer", request, env);
  }
  if (normalizedPath === `${adminRoot}/keys/admin/rotate` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleRotateByKind("admin", request, env);
  }
  if (normalizedPath === `${adminRoot}/keys` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleKeysStatusGet(env);
  }

  if (normalizedPath === `${adminRoot}/config` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleConfigGet(env);
  }
  if (normalizedPath === `${adminRoot}/config` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleConfigPut(request, env);
  }
  if (normalizedPath === `${adminRoot}/config/validate` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleConfigValidate(request, env);
  }
  if (normalizedPath === `${adminRoot}/config/test-rule` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleConfigTestRule(request, env);
  }
  if (normalizedPath === `${adminRoot}/key-rotation-config` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleKeyRotationConfigGet(env);
  }
  if (normalizedPath === `${adminRoot}/key-rotation-config` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleKeyRotationConfigPut(request, env);
  }
  if (normalizedPath === `${adminRoot}/transform-config` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleTransformConfigGet(env);
  }
  if (normalizedPath === `${adminRoot}/transform-config` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleTransformConfigPut(request, env);
  }

  if (normalizedPath === `${adminRoot}/debug` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugGet(env);
  }
  if (normalizedPath === `${adminRoot}/debug` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugPut(request, env);
  }
  if (normalizedPath === `${adminRoot}/debug` && request.method === "DELETE") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugDelete(env);
  }
  if (normalizedPath === `${adminRoot}/debug/last` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugLastGet(request);
  }
  if (normalizedPath === `${adminRoot}/live-log/stream` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleLiveLogStream(env);
  }

  if (normalizedPath === `${adminRoot}/debug/loggingSecret` && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugLoggingSecretPut(request, env);
  }
  if (normalizedPath === `${adminRoot}/debug/loggingSecret` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugLoggingSecretGet(env);
  }
  if (normalizedPath === `${adminRoot}/debug/loggingSecret` && request.method === "DELETE") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleDebugLoggingSecretDelete(env);
  }

  if (normalizedPath.startsWith(`${adminRoot}/http-auth/`)) {
    await auth.requireAdminAuth(request, env);
    return handlers.handleHttpAuthSecretRoute(normalizedPath, request, env);
  }
  if (normalizedPath.startsWith(`${adminRoot}/http-secrets/`)) {
    await auth.requireAdminAuth(request, env);
    return handlers.handleHttpSecretRoute(normalizedPath, request, env);
  }
  if (normalizedPath === `${adminRoot}/headers` && request.method === "GET") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleEnrichedHeadersList(env);
  }
  if (normalizedPath.startsWith(`${adminRoot}/headers/`) && request.method === "PUT") {
    await auth.requireAdminAuth(request, env);
    const headerName = normalizedPath.slice(`${adminRoot}/headers/`.length);
    return handlers.handleEnrichedHeaderPut(request, env, headerName);
  }
  if (normalizedPath.startsWith(`${adminRoot}/headers/`) && request.method === "DELETE") {
    await auth.requireAdminAuth(request, env);
    const headerName = normalizedPath.slice(`${adminRoot}/headers/`.length);
    return handlers.handleEnrichedHeaderDelete(env, headerName);
  }

  return null;
}

export { dispatchAdminRoute };
