package io.quarkiverse.authorization.server.runtime.config;

/** Plain unit-test configuration; actual ConfigMapping assembly is tested with QuarkusUnitTest. */
public record TestOidcConfig(boolean enabled, boolean clientRegistrationEnabled) implements AuthorizationServerOidcConfig {
}
