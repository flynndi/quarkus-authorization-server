package io.quarkiverse.authorization.server.grant.devicecode;

import java.util.Map;

import io.quarkiverse.authorization.server.grant.TokenGrantRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;

/** Protocol input for the OAuth 2.0 Device Access Token Request. */
public final class DeviceCodeExchangeRequest extends TokenGrantRequest {

    private final String deviceCode;

    public DeviceCodeExchangeRequest(
            String deviceCode,
            SecurityIdentity clientPrincipal,
            Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.DEVICE_CODE, clientPrincipal, additionalParameters);
        if (deviceCode == null || deviceCode.isBlank()) {
            throw new IllegalArgumentException("deviceCode cannot be empty");
        }
        this.deviceCode = deviceCode;
    }

    public String getDeviceCode() {
        return this.deviceCode;
    }
}
