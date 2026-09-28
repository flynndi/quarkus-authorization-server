package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.vertx.http.security.HttpSecurity;

/**
 * Requires a resource-owner identity at the Device Verification Endpoint.
 */
public final class OAuth2DeviceVerificationEndpointSecurityConfiguration {

    private final AuthorizationServerSettings authorizationServerSettings;

    @Inject
    public OAuth2DeviceVerificationEndpointSecurityConfiguration(
            AuthorizationServerSettings authorizationServerSettings) {
        this.authorizationServerSettings = authorizationServerSettings;
    }

    @Inject
    io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints endpoints;

    void configure(@Observes HttpSecurity httpSecurity) {
        String[] deviceVerificationEndpoint = this.endpoints
                .paths(this.authorizationServerSettings.getDeviceVerificationEndpoint());
        httpSecurity.get(deviceVerificationEndpoint).authenticated();
        httpSecurity.post(deviceVerificationEndpoint).authenticated();
    }
}
