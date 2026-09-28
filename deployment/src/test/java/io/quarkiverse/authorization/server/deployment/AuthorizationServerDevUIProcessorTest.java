package io.quarkiverse.authorization.server.deployment;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;
import io.smallrye.config.SmallRyeConfigBuilder;

class AuthorizationServerDevUIProcessorTest {
    @Test
    void defaultOverviewOnlyLinksToReadOnlyDocuments() {
        var overview = AuthorizationServerDevUIProcessorTest.overview("/");
        Assertions.assertEquals(8, overview.get("endpoints").size());
        Assertions.assertEquals(List.of("/oauth2/jwks", "/.well-known/oauth-authorization-server"),
                AuthorizationServerDevUIProcessorTest.readablePaths(overview));
        Assertions.assertFalse(overview.get("multipleIssuers").asBoolean());
        overview.get("features").forEach(feature -> Assertions.assertFalse(feature.get("enabled").asBoolean()));
    }

    @Test
    void enabledFeaturesAndCustomPathsUseEffectiveHttpRoot() {
        var overview = AuthorizationServerDevUIProcessorTest.overview("/api", "oidc.enabled=true",
                "oidc.client-registration.enabled=true", "client-registration.enabled=true",
                "pushed-authorization-requests-enabled=true", "default-login-page-enabled=true",
                "token-endpoint=/custom/./token");
        Assertions.assertEquals("/api/", overview.get("httpRoot").asText());
        Assertions.assertEquals(14, overview.get("endpoints").size());
        overview.get("features").forEach(feature -> Assertions.assertTrue(feature.get("enabled").asBoolean()));
        Assertions.assertEquals("/api/custom/token",
                AuthorizationServerDevUIProcessorTest.endpoint(overview, "token-endpoint").get("path").asText());
        var par = AuthorizationServerDevUIProcessorTest.endpoint(overview, "pushed-authorization-request-endpoint");
        Assertions.assertEquals("[\"POST\"]", par.get("methods").toString());
        Assertions.assertEquals("Other methods return 405", par.get("note").asText());
        Assertions.assertEquals(List.of("/api/oauth2/jwks", "/api/.well-known/oauth-authorization-server",
                "/api/.well-known/openid-configuration"), AuthorizationServerDevUIProcessorTest.readablePaths(overview));
    }

    @Test
    void multipleIssuersRenderTemplatesIncludingRfc8414DiscoveryOrder() {
        var overview = AuthorizationServerDevUIProcessorTest.overview("/api", "multiple-issuers-allowed=true",
                "oidc.enabled=true");
        Assertions.assertTrue(overview.get("multipleIssuers").asBoolean());
        // These documents become navigable only after the runtime service resolves an explicit tenant.
        Assertions.assertEquals(3, AuthorizationServerDevUIProcessorTest.readablePaths(overview).size());
        Assertions.assertEquals("/api/{issuer}/oauth2/token",
                AuthorizationServerDevUIProcessorTest.endpoint(overview, "token-endpoint").get("path").asText());
        Assertions.assertEquals("/oauth2/token",
                AuthorizationServerDevUIProcessorTest.endpoint(overview, "token-endpoint").get("issuerPath").asText());
        Assertions.assertEquals("/.well-known/oauth-authorization-server/api/{issuer}",
                AuthorizationServerDevUIProcessorTest.endpoint(overview, "OAuth authorization server metadata").get("path")
                        .asText());
        Assertions.assertEquals("/api/{issuer}/.well-known/openid-configuration",
                AuthorizationServerDevUIProcessorTest.endpoint(overview, "OIDC provider configuration").get("path").asText());
    }

    @Test
    void registrationRequiresOidcAndSharedPathsKeepTheirSeparateMethods() {
        var overview = AuthorizationServerDevUIProcessorTest.overview("/", "oidc.client-registration.enabled=true",
                "jwk-set-endpoint=/oauth2/token");
        Assertions.assertEquals(8, overview.get("endpoints").size());
        overview.get("features").forEach(feature -> Assertions.assertFalse(feature.get("enabled").asBoolean()));
        Assertions.assertEquals("[\"GET\"]",
                AuthorizationServerDevUIProcessorTest.endpoint(overview, "jwk-set-endpoint").get("methods").toString());
        Assertions.assertEquals("[\"POST\"]",
                AuthorizationServerDevUIProcessorTest.endpoint(overview, "token-endpoint").get("methods").toString());
    }

    private static JsonNode overview(String root, String... properties) {
        var builder = new SmallRyeConfigBuilder().withMapping(AuthorizationServerBuildTimeConfig.class)
                .withMapping(AuthorizationServerOidcConfig.class)
                .withMapping(AuthorizationServerClientRegistrationConfig.class);
        for (String property : properties) {
            int separator = property.indexOf('=');
            builder.withDefaultValue("quarkus.authorization-server." + property.substring(0, separator),
                    property.substring(separator + 1));
        }
        var config = builder.build();
        var card = new AuthorizationServerDevUIProcessor().overview(
                config.getConfigMapping(AuthorizationServerBuildTimeConfig.class),
                config.getConfigMapping(AuthorizationServerOidcConfig.class),
                config.getConfigMapping(AuthorizationServerClientRegistrationConfig.class),
                new HttpRootPathBuildItem(root));
        return new ObjectMapper().valueToTree(card.getBuildTimeData().get("overview").getContent());
    }

    private static JsonNode endpoint(JsonNode overview, String name) {
        for (JsonNode endpoint : overview.get("endpoints")) {
            if (endpoint.get("name").asText().equals(name)
                    || endpoint.get("name").asText().equals("quarkus.authorization-server." + name)) {
                return endpoint;
            }
        }
        throw new AssertionError("Missing endpoint: " + name);
    }

    private static List<String> readablePaths(JsonNode overview) {
        List<String> paths = new ArrayList<>();
        overview.get("endpoints").forEach(endpoint -> {
            if (endpoint.get("readable").asBoolean()) {
                paths.add(endpoint.get("path").asText());
            }
        });
        return paths;
    }
}
