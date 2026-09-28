package io.quarkiverse.authorization.server.grant.authorizationcode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.SecurityIdentity;

/** An immutable consent submission from the resource owner. */
public final class ConsentSubmission {

    /** Local consent form fields, not OAuth authorization request parameters. */
    public static final String ACTION_PARAMETER = "consent_action";
    public static final String APPROVE_ACTION = "approve";
    public static final String DENY_ACTION = "deny";

    private final String authorizationUri;
    private final String clientId;
    private final SecurityIdentity principal;
    private final String state;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;

    public ConsentSubmission(
            String authorizationUri,
            String clientId,
            SecurityIdentity principal,
            String state,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        this.authorizationUri = Arguments.requireNonBlank(authorizationUri, "authorizationUri");
        this.clientId = Arguments.requireNonBlank(clientId, "clientId");
        this.principal = Objects.requireNonNull(principal, "principal cannot be null");
        this.state = Arguments.requireNonBlank(state, "state");
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

    public String getState() {
        return this.state;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    public boolean isDenied() {
        return DENY_ACTION.equals(this.additionalParameters.get(ACTION_PARAMETER));
    }
}
