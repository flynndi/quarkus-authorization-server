package io.quarkiverse.authorization.server.runtime.oidc.registration;

import java.util.Objects;

import io.quarkus.security.identity.SecurityIdentity;

/** Immutable input for OidcClientConfigurationRequest; contains no protocol completion state. */
public final class OidcClientConfigurationRequest {
    private final SecurityIdentity principal;
    private final String clientId;

    public OidcClientConfigurationRequest(SecurityIdentity principal, String clientId) {
        this.principal = Objects.requireNonNull(principal, "principal cannot be null");
        if (clientId == null || clientId.isBlank())
            throw new IllegalArgumentException("clientId cannot be empty");
        this.clientId = clientId;
    }

    public SecurityIdentity getPrincipal() {
        return this.principal;
    }

    public String getClientId() {
        return this.clientId;
    }
}
