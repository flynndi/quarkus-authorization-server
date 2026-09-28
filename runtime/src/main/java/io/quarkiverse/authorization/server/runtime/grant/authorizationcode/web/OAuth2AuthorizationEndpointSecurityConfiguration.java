package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.vertx.http.runtime.security.AuthenticatedHttpSecurityPolicy;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.quarkus.vertx.http.security.HttpSecurity;
import io.smallrye.mutiny.Uni;

/** Initial requests reach protocol validation; consent submissions still require a resource-owner identity. */
public final class OAuth2AuthorizationEndpointSecurityConfiguration {

    private static final AuthenticatedHttpSecurityPolicy AUTHENTICATED = new AuthenticatedHttpSecurityPolicy();

    private final AuthorizationServerSettings authorizationServerSettings;

    @Inject
    public OAuth2AuthorizationEndpointSecurityConfiguration(
            AuthorizationServerSettings authorizationServerSettings) {
        this.authorizationServerSettings = authorizationServerSettings;
    }

    @Inject
    io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints endpoints;

    void configure(@Observes HttpSecurity httpSecurity) {
        String[] authorizationEndpoint = this.endpoints.paths(this.authorizationServerSettings.getAuthorizationEndpoint());
        // A valid initial request decides between silent errors and the host's login challenge.
        httpSecurity.get(authorizationEndpoint).permit();
        httpSecurity.post(authorizationEndpoint)
                .policy((request, identity,
                        requestContext) -> (request.request().formAttributes().contains(OAuth2ParameterNames.RESPONSE_TYPE)
                                || request.request().formAttributes().contains(OAuth2ParameterNames.REQUEST_URI))
                                        ? Uni.createFrom().item(HttpSecurityPolicy.CheckResult.PERMIT)
                                        : AUTHENTICATED.checkPermission(request, identity, requestContext));
    }
}
