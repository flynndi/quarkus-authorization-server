package io.quarkiverse.authorization.server.model;

import java.io.Serial;
import java.io.Serializable;

/**
 * An OAuth 2.0 authorization grant type.
 */
public final class AuthorizationGrantType implements Serializable {

    @Serial
    private static final long serialVersionUID = -1400231033837026526L;

    public static final AuthorizationGrantType AUTHORIZATION_CODE = new AuthorizationGrantType("authorization_code");
    public static final AuthorizationGrantType CLIENT_CREDENTIALS = new AuthorizationGrantType("client_credentials");
    public static final AuthorizationGrantType DEVICE_CODE = new AuthorizationGrantType(
            "urn:ietf:params:oauth:grant-type:device_code");
    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");
    public static final AuthorizationGrantType REFRESH_TOKEN = new AuthorizationGrantType("refresh_token");
    public static final AuthorizationGrantType TOKEN_EXCHANGE = new AuthorizationGrantType(
            "urn:ietf:params:oauth:grant-type:token-exchange");

    private final String value;

    public AuthorizationGrantType(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("value cannot be empty");
        }
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        return object instanceof AuthorizationGrantType that && this.value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return getValue().hashCode();
    }
}
