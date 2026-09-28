package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.smallrye.config.ConfigValidationException;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

class AuthorizationServerBuildTimeConfigTest {

    @Test
    void authorizationServerIsEnabledByDefault() {
        AuthorizationServerBuildTimeConfig config = config().getConfigMapping(AuthorizationServerBuildTimeConfig.class);

        assertTrue(config.enabled());
        assertFalse(config.defaultLoginPageEnabled());
        assertEquals("/oauth2/token", config.tokenEndpoint());
        assertEquals("/oauth2/introspect", config.tokenIntrospectionEndpoint());
        assertEquals("/oauth2/revoke", config.tokenRevocationEndpoint());
        assertEquals("/oauth2/jwks", config.jwkSetEndpoint());
    }

    @Test
    void extensionCanBeDisabledExplicitly() {
        AuthorizationServerBuildTimeConfig config = config("quarkus.authorization-server.enabled=false")
                .getConfigMapping(AuthorizationServerBuildTimeConfig.class);

        assertFalse(config.enabled());
    }

    @Test
    void endpointPathsCanBeConfiguredAtBuildTime() {
        AuthorizationServerBuildTimeConfig config = config(
                "quarkus.authorization-server.token-endpoint=/auth/token",
                "quarkus.authorization-server.token-introspection-endpoint=/auth/check-token",
                "quarkus.authorization-server.token-revocation-endpoint=/auth/revoke-token",
                "quarkus.authorization-server.jwk-set-endpoint=/auth/keys")
                .getConfigMapping(AuthorizationServerBuildTimeConfig.class);

        assertEquals("/auth/token", config.tokenEndpoint());
        assertEquals("/auth/check-token", config.tokenIntrospectionEndpoint());
        assertEquals("/auth/revoke-token", config.tokenRevocationEndpoint());
        assertEquals("/auth/keys", config.jwkSetEndpoint());
    }

    @ParameterizedTest
    @ValueSource(strings = { "authorization-endpoint", "device-authorization-endpoint", "device-verification-endpoint",
            "token-endpoint", "jwk-set-endpoint", "token-revocation-endpoint", "token-introspection-endpoint",
            "oidc-client-registration-endpoint", "oidc-user-info-endpoint", "oidc-logout-endpoint" })
    void rejectsInvalidEndpointAtConfigurationBinding(String endpoint) {
        String property = "quarkus.authorization-server." + endpoint;

        ConfigValidationException failure = assertThrows(ConfigValidationException.class,
                () -> config(property + "=https://example.com/oauth2/token"));

        assertTrue(failure.getMessage().contains(property), failure.getMessage());
        assertTrue(failure.getMessage().contains("Authorization Server endpoint must be an absolute path"),
                failure.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = { "", " \t", "\u2003", "oauth2/token", "/", "//oauth2/token",
            "/oauth2/token?x=1", "/oauth2/token#fragment" })
    void rejectsInvalidPathSyntaxWithoutRunningBuildSteps(String endpoint) {
        ConfigValidationException failure = assertThrows(ConfigValidationException.class,
                () -> config("quarkus.authorization-server.token-endpoint=" + endpoint));

        assertTrue(failure.getMessage().contains("quarkus.authorization-server.token-endpoint"), failure.getMessage());
    }

    @Test
    void preservesConfiguredPathForSettingsAndMetadata() {
        AuthorizationServerBuildTimeConfig config = config("quarkus.authorization-server.token-endpoint=/auth/token/")
                .getConfigMapping(AuthorizationServerBuildTimeConfig.class);

        assertEquals("/auth/token/", config.tokenEndpoint());
    }

    @Test
    void validatesExplicitEndpointConfigurationEvenWhenExtensionIsDisabled() {
        assertThrows(ConfigValidationException.class,
                () -> config("quarkus.authorization-server.enabled=false",
                        "quarkus.authorization-server.token-endpoint=https://example.com/oauth2/token"));
    }

    private static SmallRyeConfig config(String... properties) {
        SmallRyeConfigBuilder builder = new SmallRyeConfigBuilder()
                .withMapping(AuthorizationServerBuildTimeConfig.class);
        for (String property : properties) {
            int separator = property.indexOf('=');
            builder.withDefaultValue(property.substring(0, separator), property.substring(separator + 1));
        }
        return builder.build();
    }
}
