package io.quarkiverse.authorization.server.model;

import java.io.Serial;
import java.io.Serializable;

/**
 * An OAuth 2.0 client authentication method.
 */
public final class ClientAuthenticationMethod implements Serializable {

    @Serial
    private static final long serialVersionUID = -656149463420871695L;

    public static final ClientAuthenticationMethod CLIENT_SECRET_BASIC = new ClientAuthenticationMethod("client_secret_basic");
    public static final ClientAuthenticationMethod CLIENT_SECRET_POST = new ClientAuthenticationMethod("client_secret_post");
    public static final ClientAuthenticationMethod CLIENT_SECRET_JWT = new ClientAuthenticationMethod("client_secret_jwt");
    public static final ClientAuthenticationMethod TLS_CLIENT_AUTH = new ClientAuthenticationMethod("tls_client_auth");
    public static final ClientAuthenticationMethod SELF_SIGNED_TLS_CLIENT_AUTH = new ClientAuthenticationMethod(
            "self_signed_tls_client_auth");
    public static final ClientAuthenticationMethod PRIVATE_KEY_JWT = new ClientAuthenticationMethod("private_key_jwt");
    public static final ClientAuthenticationMethod NONE = new ClientAuthenticationMethod("none");

    private final String value;

    public ClientAuthenticationMethod(String value) {
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
        return object instanceof ClientAuthenticationMethod that && this.value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return getValue().hashCode();
    }

    @Override
    public String toString() {
        return this.value;
    }
}
