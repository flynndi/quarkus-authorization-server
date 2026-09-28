package io.quarkiverse.authorization.server.grant.devicecode;

/**
 * Customizes validated device consent before it is saved. The service invokes application CDI beans
 * in ArC priority order within the protocol request context.
 */
@FunctionalInterface
public interface DeviceConsentCustomizer {
    void customize(DeviceAuthorizationConsentContext context);
}
