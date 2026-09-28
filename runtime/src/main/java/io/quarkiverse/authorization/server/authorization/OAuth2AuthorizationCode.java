package io.quarkiverse.authorization.server.authorization;

import java.io.Serial;
import java.time.Instant;

import io.quarkiverse.authorization.server.token.AbstractOAuth2Token;

/**
 * An OAuth 2.0 Authorization Code.
 */
public class OAuth2AuthorizationCode extends AbstractOAuth2Token {

    @Serial
    private static final long serialVersionUID = -2970616894400658821L;

    public OAuth2AuthorizationCode(String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenValue, issuedAt, expiresAt);
    }
}
