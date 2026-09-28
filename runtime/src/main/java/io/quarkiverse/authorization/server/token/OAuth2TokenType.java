package io.quarkiverse.authorization.server.token;

import java.io.Serial;
import java.io.Serializable;

/**
 * The type of an OAuth 2.0 Token.
 */
public final class OAuth2TokenType implements Serializable {

    @Serial
    private static final long serialVersionUID = 7802072859961374493L;

    public static final OAuth2TokenType ACCESS_TOKEN = new OAuth2TokenType("access_token");
    public static final OAuth2TokenType REFRESH_TOKEN = new OAuth2TokenType("refresh_token");

    private final String value;

    public OAuth2TokenType(String value) {
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
        return this == object || object instanceof OAuth2TokenType that && this.value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }
}
