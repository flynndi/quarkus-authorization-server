package io.quarkiverse.authorization.server.oidc.logout;

import java.util.Objects;

import io.quarkiverse.authorization.server.client.RegisteredClient;

/** Validated protocol input and state passed to application policy. */
public record OidcLogoutContext(OidcLogoutRequest request, RegisteredClient registeredClient) {
    public OidcLogoutContext {
        Objects.requireNonNull(request, "request cannot be null");
        Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
    }
}
