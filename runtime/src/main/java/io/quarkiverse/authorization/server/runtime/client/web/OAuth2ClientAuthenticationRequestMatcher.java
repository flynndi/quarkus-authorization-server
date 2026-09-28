package io.quarkiverse.authorization.server.runtime.client.web;

import java.util.Objects;
import java.util.Set;

import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/**
 * Matches the Authorization Server endpoints that require OAuth 2.0 client authentication.
 */
public final class OAuth2ClientAuthenticationRequestMatcher {

    private final Set<Endpoint> endpoints;
    private final Set<Endpoint> publicClientEndpoints;

    public OAuth2ClientAuthenticationRequestMatcher(
            Set<Endpoint> endpoints, Set<Endpoint> publicClientEndpoints) {
        this.endpoints = Set.copyOf(Objects.requireNonNull(endpoints, "endpoints cannot be null"));
        this.publicClientEndpoints = Set.copyOf(publicClientEndpoints);
        if (!this.endpoints.containsAll(this.publicClientEndpoints)) {
            throw new IllegalArgumentException(
                    "Public client endpoints must be client authentication endpoints");
        }
    }

    public boolean matches(RoutingContext context) {
        return this.endpoints.contains(
                new Endpoint(context.request().method(),
                        io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints.protocolPath(context)));
    }

    /** Endpoint access policy; grant eligibility is validated by the grant itself. */
    public boolean allowsPublicClient(RoutingContext context) {
        return this.publicClientEndpoints.contains(
                new Endpoint(context.request().method(),
                        io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints.protocolPath(context)));
    }

    public record Endpoint(HttpMethod method, String path) {

        public Endpoint {
            Objects.requireNonNull(method, "method cannot be null");
            path = HttpSecurityUtils.normalizePath(
                    Objects.requireNonNull(path, "path cannot be null"));
        }
    }
}
