package io.quarkiverse.authorization.server.grant.authorizationcode;

import java.util.Map;

import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;

/** Protocol input for the OAuth 2.0 Authorization Code Grant. */
public final class AuthorizationCodeExchangeRequest
        extends TokenGrantRequest {

    private final String code;
    private final String redirectUri;

    public AuthorizationCodeExchangeRequest(
            String code,
            SecurityIdentity clientPrincipal,
            String redirectUri,
            Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.AUTHORIZATION_CODE, clientPrincipal, additionalParameters);
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("code cannot be empty");
        }
        this.code = code;
        this.redirectUri = redirectUri;
    }

    public String getCode() {
        return this.code;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }
}
