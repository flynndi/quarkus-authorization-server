package io.quarkiverse.authorization.server.runtime.oidc.web;

import java.util.Objects;

import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Exact GET/POST UserInfo matching, with the HTTP root path resolved by deployment. */
public final class OidcUserInfoEndpointRequestMatcher {
    private final String path;

    public OidcUserInfoEndpointRequestMatcher(String path) {
        this.path = HttpSecurityUtils.normalizePath(Objects.requireNonNull(path, "path cannot be null"));
    }

    public boolean matches(RoutingContext context) {
        return (context.request().method() == HttpMethod.GET || context.request().method() == HttpMethod.POST)
                && this.path.equals(HttpSecurityUtils.normalizePath(
                        io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints.protocolPath(context)));
    }
}
