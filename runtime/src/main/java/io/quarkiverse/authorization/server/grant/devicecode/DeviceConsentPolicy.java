package io.quarkiverse.authorization.server.grant.devicecode;

/**
 * Decides whether a validated device verification needs consent. One application CDI bean replaces
 * the default decision; code and client validation remain the service's responsibility.
 */
@FunctionalInterface
public interface DeviceConsentPolicy {
    /** Whether new scope consent is needed. Returning false never skips device confirmation. */
    boolean isConsentRequired(DeviceVerificationContext context);
}
