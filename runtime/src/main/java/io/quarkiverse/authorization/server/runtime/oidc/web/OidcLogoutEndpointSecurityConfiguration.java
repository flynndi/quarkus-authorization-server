package io.quarkiverse.authorization.server.runtime.oidc.web;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.vertx.http.security.HttpSecurity;

/** Logout may be requested without an active OP session; the protocol provider still validates the hint. */
public final class OidcLogoutEndpointSecurityConfiguration {
    private final AuthorizationServerSettings settings;

    @Inject
    public OidcLogoutEndpointSecurityConfiguration(AuthorizationServerSettings settings) {
        this.settings = settings;
    }

    @Inject
    io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints endpoints;

    void configure(@Observes HttpSecurity security) {
        String[] path = this.endpoints.paths(this.settings.getOidcLogoutEndpoint());
        security.path(path).permit();
        security.get(path).permit();
        security.post(path).permit();
    }
}
