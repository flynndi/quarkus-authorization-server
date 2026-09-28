package io.quarkiverse.authorization.server.oidc.registration;

import java.util.Objects;

import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkus.security.identity.SecurityIdentity;

/** Immutable input for OidcClientRegistrationRequest; contains no protocol completion state. */
public final class OidcClientRegistrationRequest {
    private final SecurityIdentity principal;
    private final OidcClientRegistration clientRegistration;

    public OidcClientRegistrationRequest(
            SecurityIdentity principal, OidcClientRegistration clientRegistration) {
        this.principal = Objects.requireNonNull(principal, "principal cannot be null");
        this.clientRegistration = Objects.requireNonNull(clientRegistration, "clientRegistration cannot be null");
    }

    public SecurityIdentity getPrincipal() {
        return this.principal;
    }

    public OidcClientRegistration getClientRegistration() {
        return this.clientRegistration;
    }
}
