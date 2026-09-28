package io.quarkiverse.authorization.server.grant.devicecode;

import java.util.Objects;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.RegisteredClient;

/** Validated protocol input and state passed to application policy. */
public record DeviceAuthorizationConsentContext(
        DeviceConsentSubmission request,
        OAuth2AuthorizationConsent.Builder authorizationConsent,
        RegisteredClient registeredClient,
        OAuth2Authorization authorization) {
    public DeviceAuthorizationConsentContext {
        Objects.requireNonNull(request, "request cannot be null");
        Objects.requireNonNull(authorizationConsent, "authorizationConsent cannot be null");
        Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
        Objects.requireNonNull(authorization, "authorization cannot be null");
    }
}
