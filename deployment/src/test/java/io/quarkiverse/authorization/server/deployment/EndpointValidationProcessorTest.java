package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;
import io.smallrye.config.SmallRyeConfigBuilder;

class EndpointValidationProcessorTest {
    @ParameterizedTest
    @ValueSource(strings = { "authorization-endpoint", "device-authorization-endpoint", "device-verification-endpoint",
            "token-introspection-endpoint", "token-revocation-endpoint", "pushed-authorization-request-endpoint",
            "client-registration-endpoint", "oidc-client-registration-endpoint", "oidc-user-info-endpoint",
            "oidc-logout-endpoint" })
    void diagnosesEnabledPostEndpointsWithPropertyNamesAndEffectivePath(String property) {
        var error = Assertions.assertThrows(ConfigurationException.class, () -> EndpointValidationProcessorTest.validate(
                "pushed-authorization-requests-enabled=true", "client-registration.enabled=true",
                "oidc.enabled=true", "oidc.client-registration.enabled=true", property + "=/oauth2/token"));
        Assertions.assertTrue(error.getMessage().contains("quarkus.authorization-server." + property));
        Assertions.assertTrue(error.getMessage().contains("quarkus.authorization-server.token-endpoint"));
        Assertions.assertTrue(error.getMessage().contains("/api/oauth2/token"));
        Assertions.assertTrue(error.getMessage().contains("POST"));
    }

    @Test
    void disabledFeaturesDoNotReserveTheirPaths() {
        EndpointValidationProcessorTest.validate("pushed-authorization-request-endpoint=/oauth2/token",
                "client-registration-endpoint=/oauth2/token", "oidc-client-registration-endpoint=/oauth2/token",
                "oidc-user-info-endpoint=/oauth2/token", "oidc-logout-endpoint=/oauth2/token",
                "oidc.client-registration.enabled=true");
        EndpointValidationProcessorTest.validate("enabled=false", "authorization-endpoint=/oauth2/token");
        EndpointValidationProcessorTest.validate("oidc.enabled=true", "oidc-client-registration-endpoint=/oauth2/token");
    }

    @Test
    void permitsTheSamePathForDisjointMethods() {
        EndpointValidationProcessorTest.validate("jwk-set-endpoint=/oauth2/token");
        EndpointValidationProcessorTest.validate("token-endpoint=/.well-known/oauth-authorization-server");
    }

    @Test
    void parAlsoReservesGetToReturnItsOwnMethodNotAllowedResponse() {
        var error = Assertions.assertThrows(ConfigurationException.class, () -> EndpointValidationProcessorTest.validate(
                "pushed-authorization-requests-enabled=true", "pushed-authorization-request-endpoint=/oauth2/jwks"));
        Assertions.assertTrue(error.getMessage().contains("GET"));
        Assertions.assertTrue(error.getMessage().contains("jwk-set-endpoint"));
    }

    @Test
    void includesFixedDiscoveryRoutesAndNormalizesPathsLikeQuarkus() {
        Assertions.assertThrows(ConfigurationException.class, () -> EndpointValidationProcessorTest.validate(
                "jwk-set-endpoint=/.well-known/oauth-authorization-server"));
        Assertions.assertThrows(ConfigurationException.class, () -> EndpointValidationProcessorTest.validate(
                "oidc.enabled=true", "jwk-set-endpoint=/.well-known/openid-configuration"));
        Assertions.assertThrows(ConfigurationException.class, () -> EndpointValidationProcessorTest.validate(
                "token-endpoint=/oauth2/./authorize/"));
        EndpointValidationProcessorTest.validate("jwk-set-endpoint=/.well-known/openid-configuration");
    }

    @Test
    void includesIssuerPrefixesAndIssuerSpecificDiscoveryRoutes() {
        EndpointValidationProcessorTest.validate("multiple-issuers-allowed=true", "oidc.enabled=true");
        var error = Assertions.assertThrows(ConfigurationException.class, () -> EndpointValidationProcessorTest.validate(
                "multiple-issuers-allowed=true", "token-endpoint=/oauth2/authorize"));
        Assertions.assertTrue(error.getMessage().contains("/api/:issuer/oauth2/authorize"));
        Assertions.assertThrows(ConfigurationException.class, () -> EndpointValidationProcessorTest.validate(
                "multiple-issuers-allowed=true", "oidc.enabled=true", "jwk-set-endpoint=/.well-known/openid-configuration"));
    }

    private static void validate(String... properties) {
        EndpointValidationProcessorTest.validateAtRoot("/api", properties);
    }

    @Test
    void discoveryPrefixIsNotTreatedAsAValidTenantId() {
        EndpointValidationProcessorTest.validateAtRoot("/", "multiple-issuers-allowed=true",
                "jwk-set-endpoint=/oauth-authorization-server/example");
    }

    private static void validateAtRoot(String rootPath, String... properties) {
        var builder = new SmallRyeConfigBuilder().withMapping(AuthorizationServerBuildTimeConfig.class)
                .withMapping(AuthorizationServerOidcConfig.class)
                .withMapping(AuthorizationServerClientRegistrationConfig.class);
        for (String property : properties) {
            int separator = property.indexOf('=');
            builder.withDefaultValue("quarkus.authorization-server." + property.substring(0, separator),
                    property.substring(separator + 1));
        }
        var config = builder.build();
        EndpointValidationProcessor.validate(config.getConfigMapping(AuthorizationServerBuildTimeConfig.class),
                config.getConfigMapping(AuthorizationServerOidcConfig.class),
                config.getConfigMapping(AuthorizationServerClientRegistrationConfig.class),
                new HttpRootPathBuildItem(rootPath));
    }
}
