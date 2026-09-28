package io.quarkiverse.authorization.server.token;

import java.io.Serializable;
import java.time.Instant;

/**
 * An OAuth 2.0 Token.
 */
public interface OAuth2Token extends Serializable {

    String getTokenValue();

    Instant getIssuedAt();

    Instant getExpiresAt();
}
