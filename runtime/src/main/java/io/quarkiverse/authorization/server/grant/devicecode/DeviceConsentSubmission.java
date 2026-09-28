package io.quarkiverse.authorization.server.grant.devicecode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import io.quarkus.security.identity.SecurityIdentity;

/** Immutable input for DeviceConsentSubmission; contains no protocol completion state. */
public final class DeviceConsentSubmission {
    private final String clientId;
    private final SecurityIdentity principal;
    private final String userCode;
    private final String state;
    private final boolean approved;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;

    public DeviceConsentSubmission(
            String clientId,
            SecurityIdentity principal,
            String userCode,
            String state,
            boolean approved,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        if (clientId == null || clientId.isBlank())
            throw new IllegalArgumentException("clientId cannot be empty");
        this.clientId = clientId;
        this.principal = Objects.requireNonNull(principal, "principal cannot be null");
        if (userCode == null || userCode.isBlank())
            throw new IllegalArgumentException("userCode cannot be empty");
        this.userCode = userCode;
        if (state == null || state.isBlank())
            throw new IllegalArgumentException("state cannot be empty");
        this.state = state;
        this.approved = approved;
        this.scopes = scopes == null
                ? Set.of()
                : Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
        this.additionalParameters = additionalParameters == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(additionalParameters));
    }

    public String getClientId() {
        return this.clientId;
    }

    public SecurityIdentity getPrincipal() {
        return this.principal;
    }

    public String getUserCode() {
        return this.userCode;
    }

    public String getState() {
        return this.state;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public boolean isApproved() {
        return this.approved;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
