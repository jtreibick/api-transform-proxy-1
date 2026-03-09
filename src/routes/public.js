async function dispatchPublicRoute({ normalizedPath, request, env, ctx, reservedRoot, handlers, auth, options = {} }) {
  const {
    enableRootProxy = true,
    enableStatusBootstrap = true,
    enableRequest = true,
    enableSelfRotate = true,
  } = options;

  if (enableRootProxy && normalizedPath === "/" && request.method === "GET") {
    if (request.headers.get("X-Proxy-Key")) {
      return handlers.handleRootProxyRequest(request, env, ctx);
    }
    if (enableStatusBootstrap) {
      return Response.redirect(new URL(`${reservedRoot}/`, request.url).toString(), 302);
    }
    return null;
  }

  if (enableStatusBootstrap && normalizedPath === reservedRoot && request.method === "GET") {
    return handlers.handleStatusPage(env, request);
  }
  if (enableStatusBootstrap && normalizedPath === reservedRoot && request.method === "POST") {
    return handlers.handleBootstrapPost(env);
  }
  if (enableRequest && normalizedPath === `${reservedRoot}/request` && request.method === "POST") {
    return handlers.handleRequest(request, env, ctx);
  }

  if (enableSelfRotate && normalizedPath === `${reservedRoot}/keys/proxy/rotate` && request.method === "POST") {
    await auth.requireProxyKey(request, env);
    return handlers.handleRotateByKind("proxy", request, env);
  }
  if (enableSelfRotate && normalizedPath === `${reservedRoot}/keys/issuer/rotate` && request.method === "POST") {
    await auth.requireIssuerKey(request, env);
    return handlers.handleRotateByKind("issuer", request, env);
  }
  if (enableSelfRotate && normalizedPath === `${reservedRoot}/keys/admin/rotate` && request.method === "POST") {
    await auth.requireAdminAuth(request, env);
    return handlers.handleRotateByKind("admin", request, env);
  }

  return null;
}

export { dispatchPublicRoute };
