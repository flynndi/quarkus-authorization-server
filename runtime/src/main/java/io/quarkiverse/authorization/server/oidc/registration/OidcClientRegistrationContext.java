package io.quarkiverse.authorization.server.oidc.registration;

import java.util.Objects;

/** Validated protocol input and state passed to application policy. */
public record OidcClientRegistrationContext(OidcClientRegistrationRequest request) {
    public OidcClientRegistrationContext {
        Objects.requireNonNull(request, "request cannot be null");
    }
}
