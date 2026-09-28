package io.quarkiverse.authorization.server.token;

import java.io.Serial;

import java.time.Instant;

/**
 * A user code issued as part of the OAuth 2.0 Device Authorization Grant.
 */
public final class OAuth2UserCode extends AbstractOAuth2Token {

    @Serial
    private static final long serialVersionUID = 9012876761508192153L;

    public OAuth2UserCode(String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenValue, issuedAt, expiresAt);
    }
}
