package io.quarkiverse.authorization.server.runtime.oidc.web;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.runtime.client.registration.web.ClientRegistrationAuthenticationMechanism;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.vertx.http.security.HttpSecurity;

public final class OidcClientRegistrationEndpointSecurityConfiguration {

    private final AuthorizationServerSettings settings;

    @Inject
    public OidcClientRegistrationEndpointSecurityConfiguration(AuthorizationServerSettings settings) {
        this.settings = settings;
    }

    @Inject
    io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints endpoints;

    void configure(@Observes HttpSecurity security) {
        String[] path = this.endpoints.paths(this.settings.getOidcClientRegistrationEndpoint());
        security.path(path).permit()
                .get(path).authenticatedWith(ClientRegistrationAuthenticationMechanism.AUTHENTICATION_SCHEME);
        security.post(path).authenticatedWith(ClientRegistrationAuthenticationMechanism.AUTHENTICATION_SCHEME);
    }
}
