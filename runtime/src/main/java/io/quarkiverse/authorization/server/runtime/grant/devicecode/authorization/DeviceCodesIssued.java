package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import java.util.Objects;

import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;

/** The persisted device/user code pair; HTTP constructs the verification URLs. */
public record DeviceCodesIssued(OAuth2DeviceCode deviceCode, OAuth2UserCode userCode) {
    public DeviceCodesIssued {
        Objects.requireNonNull(deviceCode, "deviceCode cannot be null");
        Objects.requireNonNull(userCode, "userCode cannot be null");
    }
}
