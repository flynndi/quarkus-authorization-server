package io.quarkiverse.authorization.server.settings;

import java.io.Serial;
import java.io.Serializable;

import io.quarkiverse.authorization.server.runtime.util.Arguments;

/**
 * Standard data formats for OAuth 2.0 Tokens.
 */
public final class OAuth2TokenFormat implements Serializable {

    @Serial
    private static final long serialVersionUID = 829694161026528249L;

    public static final OAuth2TokenFormat SELF_CONTAINED = new OAuth2TokenFormat("self-contained");
    public static final OAuth2TokenFormat REFERENCE = new OAuth2TokenFormat("reference");

    private final String value;

    public OAuth2TokenFormat(String value) {
        Arguments.requireNonBlank(value, "value");
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }

    @Override
    public boolean equals(Object object) {
        return this == object || object != null && getClass() == object.getClass()
                && this.value.equals(((OAuth2TokenFormat) object).value);
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }
}
