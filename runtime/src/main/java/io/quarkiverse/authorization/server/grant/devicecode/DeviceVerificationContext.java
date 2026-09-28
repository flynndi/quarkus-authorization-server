package io.quarkiverse.authorization.server.grant.devicecode;

import java.util.Objects;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.RegisteredClient;

/** Validated protocol input and state passed to application policy. */
public record DeviceVerificationContext(
        DeviceVerificationRequest request,
        RegisteredClient registeredClient,
        OAuth2Authorization authorization,
        OAuth2AuthorizationConsent authorizationConsent) {
    public DeviceVerificationContext {
        Objects.requireNonNull(request, "request cannot be null");
        Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
        Objects.requireNonNull(authorization, "authorization cannot be null");
    }
}
