package io.quarkiverse.authorization.server.runtime.client.registration.web;

import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Shared bearer boundary: OAuth POST and the enabled OIDC POST/GET, never other application routes. */
public final class ClientRegistrationEndpointRequestMatcher {
    private final String oauthPath;
    private final String oidcPath;

    public ClientRegistrationEndpointRequestMatcher(String oauthPath, String oidcPath) {
        this.oauthPath = oauthPath == null ? null : HttpSecurityUtils.normalizePath(oauthPath);
        this.oidcPath = oidcPath == null ? null : HttpSecurityUtils.normalizePath(oidcPath);
    }

    public boolean matches(RoutingContext context) {
        String path = HttpSecurityUtils.normalizePath(
                io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints.protocolPath(context));
        return context.request().method() == HttpMethod.POST && path.equals(this.oauthPath)
                || (context.request().method() == HttpMethod.POST || context.request().method() == HttpMethod.GET)
                        && path.equals(this.oidcPath);
    }
}
