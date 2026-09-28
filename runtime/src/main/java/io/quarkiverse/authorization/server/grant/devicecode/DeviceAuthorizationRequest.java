package io.quarkiverse.authorization.server.grant.devicecode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import io.quarkus.security.identity.SecurityIdentity;

/** Immutable input for DeviceAuthorizationRequest; contains no protocol completion state. */
public final class DeviceAuthorizationRequest {
    private final SecurityIdentity clientPrincipal;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;

    public DeviceAuthorizationRequest(
            SecurityIdentity clientPrincipal,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        this.clientPrincipal = Objects.requireNonNull(clientPrincipal, "clientPrincipal cannot be null");
        this.scopes = scopes == null
                ? Set.of()
                : Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
        this.additionalParameters = additionalParameters == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(additionalParameters));
    }

    public SecurityIdentity getClientPrincipal() {
        return this.clientPrincipal;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
