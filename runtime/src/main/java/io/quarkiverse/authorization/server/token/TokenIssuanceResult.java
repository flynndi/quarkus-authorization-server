package io.quarkiverse.authorization.server.token;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkus.security.identity.SecurityIdentity;

/** Tokens successfully issued and persisted by a grant operation. */
public final class TokenIssuanceResult {

    private final RegisteredClient registeredClient;
    private final SecurityIdentity clientPrincipal;
    private final OAuth2AccessToken accessToken;
    private final OAuth2RefreshToken refreshToken;
    private final Map<String, Object> additionalParameters;

    public TokenIssuanceResult(
            RegisteredClient registeredClient,
            SecurityIdentity clientPrincipal,
            OAuth2AccessToken accessToken) {
        this(registeredClient, clientPrincipal, accessToken, null);
    }

    public TokenIssuanceResult(
            RegisteredClient registeredClient,
            SecurityIdentity clientPrincipal,
            OAuth2AccessToken accessToken,
            OAuth2RefreshToken refreshToken) {
        this(registeredClient, clientPrincipal, accessToken, refreshToken, Collections.emptyMap());
    }

    public TokenIssuanceResult(
            RegisteredClient registeredClient,
            SecurityIdentity clientPrincipal,
            OAuth2AccessToken accessToken,
            OAuth2RefreshToken refreshToken,
            Map<String, Object> additionalParameters) {
        this.registeredClient = Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
        this.clientPrincipal = Objects.requireNonNull(clientPrincipal, "clientPrincipal cannot be null");
        this.accessToken = Objects.requireNonNull(accessToken, "accessToken cannot be null");
        this.refreshToken = refreshToken;
        this.additionalParameters = Map.copyOf(
                Objects.requireNonNull(
                        additionalParameters, "additionalParameters cannot be null"));
    }

    public SecurityIdentity getPrincipal() {
        return this.clientPrincipal;
    }

    public RegisteredClient getRegisteredClient() {
        return this.registeredClient;
    }

    public OAuth2AccessToken getAccessToken() {
        return this.accessToken;
    }

    public OAuth2RefreshToken getRefreshToken() {
        return this.refreshToken;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
