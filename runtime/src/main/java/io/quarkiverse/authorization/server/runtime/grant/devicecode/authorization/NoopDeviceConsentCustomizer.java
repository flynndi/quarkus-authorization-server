package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.grant.devicecode.DeviceAuthorizationConsentContext;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentCustomizer;
import io.quarkus.arc.DefaultBean;

@Singleton
@DefaultBean
public final class NoopDeviceConsentCustomizer implements DeviceConsentCustomizer {
    @Override
    public void customize(DeviceAuthorizationConsentContext context) {
    }
}
