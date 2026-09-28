package io.quarkiverse.authorization.server.runtime.oidc.web;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.vertx.http.security.HttpSecurity;

public final class OidcUserInfoEndpointSecurityConfiguration {
    private final AuthorizationServerSettings settings;

    @Inject
    public OidcUserInfoEndpointSecurityConfiguration(AuthorizationServerSettings settings) {
        this.settings = settings;
    }

    @Inject
    io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints endpoints;

    void configure(@Observes HttpSecurity security) {
        security.path(this.endpoints
                .paths(OidcProviderConfigurationEndpointHandler.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_PATH)).permit();
        String[] path = this.endpoints.paths(this.settings.getOidcUserInfoEndpoint());
        security.path(path).permit().get(path).authenticatedWith(OidcUserInfoAuthenticationMechanism.AUTHENTICATION_SCHEME);
        security.post(path).authenticatedWith(OidcUserInfoAuthenticationMechanism.AUTHENTICATION_SCHEME);
    }
}
