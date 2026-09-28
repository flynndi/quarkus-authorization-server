package io.quarkiverse.authorization.server.grant.devicecode;

import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;

/** Generates the device code returned by a validated Device Authorization request. */
@FunctionalInterface
public interface DeviceCodeGenerator {
    OAuth2DeviceCode generate(OAuth2TokenContext context);
}
