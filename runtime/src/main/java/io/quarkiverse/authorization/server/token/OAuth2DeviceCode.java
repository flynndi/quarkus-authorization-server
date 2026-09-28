package io.quarkiverse.authorization.server.token;

import java.io.Serial;

import java.time.Instant;

/**
 * A device code issued as part of the OAuth 2.0 Device Authorization Grant.
 */
public final class OAuth2DeviceCode extends AbstractOAuth2Token {

    @Serial
    private static final long serialVersionUID = 5216637471728854061L;

    public OAuth2DeviceCode(String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenValue, issuedAt, expiresAt);
    }
}
