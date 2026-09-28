package io.quarkiverse.authorization.server.endpoint;

import java.io.Serial;
import java.io.Serializable;

/**
 * An OAuth 2.0 authorization response type.
 */
public final class OAuth2AuthorizationResponseType implements Serializable {

    @Serial
    private static final long serialVersionUID = -6405510185892376280L;

    public static final OAuth2AuthorizationResponseType CODE = new OAuth2AuthorizationResponseType("code");

    private final String value;

    public OAuth2AuthorizationResponseType(String value) {
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
        return this == object
                || object instanceof OAuth2AuthorizationResponseType that && this.value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }
}
