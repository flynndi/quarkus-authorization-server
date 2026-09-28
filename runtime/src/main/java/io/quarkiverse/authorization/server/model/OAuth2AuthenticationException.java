package io.quarkiverse.authorization.server.model;

import java.io.Serial;

import io.quarkus.security.AuthenticationException;

/**
 * OAuth 2.0 authentication failure propagated through Quarkus' identity-provider pipeline.
 */
public class OAuth2AuthenticationException extends SecurityException implements AuthenticationException {

    @Serial
    private static final long serialVersionUID = -4351483285601928964L;

    private final OAuth2Error error;

    public OAuth2AuthenticationException(String errorCode) {
        this(new OAuth2Error(errorCode));
    }

    public OAuth2AuthenticationException(OAuth2Error error) {
        this(error, null);
    }

    public OAuth2AuthenticationException(OAuth2Error error, Throwable cause) {
        super(error != null ? error.getDescription() : null, cause);
        this.error = java.util.Objects.requireNonNull(error, "error cannot be null");
    }

    public OAuth2Error getError() {
        return this.error;
    }
}
