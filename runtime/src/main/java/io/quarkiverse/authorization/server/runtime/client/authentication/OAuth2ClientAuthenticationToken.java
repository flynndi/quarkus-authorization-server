package io.quarkiverse.authorization.server.runtime.client.authentication;

import java.util.Objects;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkus.security.identity.request.BaseAuthenticationRequest;

/** Authentication request used for OAuth 2.0 client authentication. */
public final class OAuth2ClientAuthenticationToken extends BaseAuthenticationRequest {

    public static final String REGISTERED_CLIENT_ATTRIBUTE = RegisteredClient.class.getName();
    public static final String CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE = ClientAuthenticationMethod.class.getName();

    private final String clientId;
    private final ClientAuthenticationMethod clientAuthenticationMethod;
    private final String credentials;

    public OAuth2ClientAuthenticationToken(
            String clientId,
            ClientAuthenticationMethod clientAuthenticationMethod,
            String credentials) {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId cannot be empty");
        }
        this.clientId = clientId;
        this.clientAuthenticationMethod = Objects.requireNonNull(clientAuthenticationMethod,
                "clientAuthenticationMethod cannot be null");
        this.credentials = credentials;
    }

    public String getPrincipal() {
        return this.clientId;
    }

    public String getCredentials() {
        return this.credentials;
    }

    public ClientAuthenticationMethod getClientAuthenticationMethod() {
        return this.clientAuthenticationMethod;
    }

}
