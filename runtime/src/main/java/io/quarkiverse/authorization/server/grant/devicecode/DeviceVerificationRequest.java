package io.quarkiverse.authorization.server.grant.devicecode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import io.quarkus.security.identity.SecurityIdentity;

/** Immutable input for DeviceVerificationRequest; contains no protocol completion state. */
public final class DeviceVerificationRequest {
    private final SecurityIdentity principal;
    private final String userCode;
    private final Map<String, Object> additionalParameters;

    public DeviceVerificationRequest(
            SecurityIdentity principal, String userCode, Map<String, Object> additionalParameters) {
        this.principal = Objects.requireNonNull(principal, "principal cannot be null");
        if (userCode == null || userCode.isBlank())
            throw new IllegalArgumentException("userCode cannot be empty");
        this.userCode = userCode;
        this.additionalParameters = additionalParameters == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(additionalParameters));
    }

    public SecurityIdentity getPrincipal() {
        return this.principal;
    }

    public String getUserCode() {
        return this.userCode;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
