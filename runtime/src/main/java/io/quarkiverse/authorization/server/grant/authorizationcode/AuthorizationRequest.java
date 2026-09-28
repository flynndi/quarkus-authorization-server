package io.quarkiverse.authorization.server.grant.authorizationcode;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.SecurityIdentity;

/** An immutable authorization request. Issued codes and consent decisions are separate results. */
public final class AuthorizationRequest {

    private final String authorizationUri;
    private final String clientId;
    private final SecurityIdentity principal;
    private final String redirectUri;
    private final String state;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;

    public AuthorizationRequest(
            String authorizationUri,
            String clientId,
            SecurityIdentity principal,
            String redirectUri,
            String state,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        this.authorizationUri = Arguments.requireNonBlank(authorizationUri, "authorizationUri");
        this.clientId = Arguments.requireNonBlank(clientId, "clientId");
        this.principal = Objects.requireNonNull(principal, "principal cannot be null");
        this.redirectUri = redirectUri;
        this.state = state;
        this.scopes = Collections.unmodifiableSet(
                scopes != null ? new LinkedHashSet<>(scopes) : Collections.emptySet());
        this.additionalParameters = Collections.unmodifiableMap(
                additionalParameters != null
                        ? new LinkedHashMap<>(additionalParameters)
                        : Collections.emptyMap());
    }

    public SecurityIdentity getPrincipal() {
        return this.principal;
    }

    public String getAuthorizationUri() {
        return this.authorizationUri;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public String getState() {
        return this.state;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    /** Prompt only has OIDC semantics when the request includes the openid scope. */
    public Set<String> getPromptValues() {
        if (this.scopes.contains(OidcScopes.OPENID)
                && this.additionalParameters.get(OidcParameterNames.PROMPT) instanceof String prompt
                && !prompt.isBlank()) {
            return Set.copyOf(Arrays.asList(prompt.split(" ")));
        }
        return Set.of();
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
