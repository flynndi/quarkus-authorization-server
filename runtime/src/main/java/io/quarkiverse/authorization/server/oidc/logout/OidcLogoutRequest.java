package io.quarkiverse.authorization.server.oidc.logout;

import java.util.Objects;

import io.quarkus.security.identity.SecurityIdentity;

/** Immutable input for OidcLogoutRequest; contains no protocol completion state. */
public final class OidcLogoutRequest {
    private final String idTokenHint;
    private final SecurityIdentity principal;
    private final String sessionId;
    private final String clientId;
    private final String postLogoutRedirectUri;
    private final String state;

    public OidcLogoutRequest(
            String idTokenHint,
            SecurityIdentity principal,
            String sessionId,
            String clientId,
            String postLogoutRedirectUri,
            String state) {
        if (idTokenHint == null || idTokenHint.isBlank())
            throw new IllegalArgumentException("idTokenHint cannot be empty");
        this.idTokenHint = idTokenHint;
        this.principal = Objects.requireNonNull(principal, "principal cannot be null");
        this.sessionId = sessionId;
        this.clientId = clientId;
        this.postLogoutRedirectUri = postLogoutRedirectUri;
        this.state = state;
    }

    public String getIdTokenHint() {
        return this.idTokenHint;
    }

    public SecurityIdentity getPrincipal() {
        return this.principal;
    }

    public String getSessionId() {
        return this.sessionId;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getPostLogoutRedirectUri() {
        return this.postLogoutRedirectUri;
    }

    public String getState() {
        return this.state;
    }
}
