package io.quarkiverse.authorization.server.grant.refreshtoken;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;

/** Protocol input for the OAuth 2.0 Refresh Token Grant. */
public final class RefreshTokenRequest extends TokenGrantRequest {

    private final String refreshToken;
    private final Set<String> scopes;

    public RefreshTokenRequest(
            String refreshToken,
            SecurityIdentity clientPrincipal,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.REFRESH_TOKEN, clientPrincipal, additionalParameters);
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("refreshToken cannot be empty");
        }
        this.refreshToken = refreshToken;
        this.scopes = Collections.unmodifiableSet(
                scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

    public String getRefreshToken() {
        return this.refreshToken;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
