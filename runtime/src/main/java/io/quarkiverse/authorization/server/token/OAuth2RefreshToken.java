package io.quarkiverse.authorization.server.token;

import java.io.Serial;

import java.time.Instant;

/**
 * An OAuth 2.0 Refresh Token.
 */
public final class OAuth2RefreshToken extends AbstractOAuth2Token {

    @Serial
    private static final long serialVersionUID = 1498770204635304142L;

    public OAuth2RefreshToken(String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenValue, issuedAt, expiresAt);
    }
}
