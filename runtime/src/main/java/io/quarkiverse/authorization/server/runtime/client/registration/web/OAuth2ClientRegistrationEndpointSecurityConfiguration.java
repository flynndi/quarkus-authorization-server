package io.quarkiverse.authorization.server.runtime.client.registration.web;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.vertx.http.security.HttpSecurity;

public final class OAuth2ClientRegistrationEndpointSecurityConfiguration {
    private final AuthorizationServerSettings settings;
    private final AuthorizationServerClientRegistrationConfig config;

    @Inject
    public OAuth2ClientRegistrationEndpointSecurityConfiguration(AuthorizationServerSettings settings,
            AuthorizationServerClientRegistrationConfig config) {
        this.settings = settings;
        this.config = config;
    }

    @Inject
    io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints endpoints;

    void configure(@Observes HttpSecurity security) {
        String[] path = this.endpoints.paths(this.settings.getClientRegistrationEndpoint());
        security.path(path).permit();
        var permission = security.post(path);
        // Select the bearer mechanism for both modes. Only the authorization policy differs.
        if (this.config.openRegistrationAllowed())
            permission.permit();
        permission.authenticatedWith(ClientRegistrationAuthenticationMechanism.AUTHENTICATION_SCHEME);
    }
}
