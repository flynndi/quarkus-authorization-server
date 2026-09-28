package io.quarkiverse.authorization.server.grant;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;

/** Immutable common data for a token grant; independent of Quarkus authentication requests. */
public abstract class TokenGrantRequest {

    private final AuthorizationGrantType authorizationGrantType;
    private final SecurityIdentity clientPrincipal;
    private final Map<String, Object> additionalParameters;

    protected TokenGrantRequest(
            AuthorizationGrantType authorizationGrantType,
            SecurityIdentity clientPrincipal,
            Map<String, Object> additionalParameters) {
        this.authorizationGrantType = Objects.requireNonNull(
                authorizationGrantType, "authorizationGrantType cannot be null");
        this.clientPrincipal = Objects.requireNonNull(clientPrincipal, "clientPrincipal cannot be null");
        this.additionalParameters = Collections.unmodifiableMap(
                additionalParameters != null
                        ? new HashMap<>(additionalParameters)
                        : Collections.emptyMap());
    }

    public AuthorizationGrantType getGrantType() {
        return this.authorizationGrantType;
    }

    public SecurityIdentity getClientPrincipal() {
        return this.clientPrincipal;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
