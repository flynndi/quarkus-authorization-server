package io.quarkiverse.authorization.server.grant.password;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;

/** Protocol input for the OAuth 2.0 Resource Owner Password Credentials grant. */
public final class PasswordGrantRequest extends TokenGrantRequest {

    private final String username;
    private final String password;
    private final Set<String> scopes;

    public PasswordGrantRequest(
            SecurityIdentity clientPrincipal,
            String username,
            String password,
            Map<String, Object> additionalParameters,
            Set<String> scopes) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username cannot be empty");
        }
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("password cannot be empty");
        }
        this.username = username;
        this.password = password;
        this.scopes = Collections.unmodifiableSet(
                scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
