package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.client.registration.ClientRegistrationScopeValidator;
import io.quarkiverse.authorization.server.client.registration.RegistrationClientSettingsCustomizer;
import io.quarkiverse.authorization.server.client.registration.RegistrationTokenSettingsCustomizer;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcProviderMetadataCustomizer;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

class OidcRegistrationCdiCompositionTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> ClientRegistrationTestApplication.baseApplication(jar)
                            .addClasses(
                                    Config.class,
                                    PolicyRequestProbe.class,
                                    PolicyRequestProbe.Observations.class));

    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    PolicyRequestProbe.Observations observations;

    @Test
    void defaultMapperUsesCdiSettingsAndDiscoveryCustomizer() {
        observations.clear();
        var response = register("allowed", "https://rp.example/callback")
                .then()
                .statusCode(201)
                .extract()
                .response();
        var client = clients.findByClientId(response.path("client_id"));
        assertEquals(Duration.ofSeconds(123), client.getTokenSettings().getAccessTokenTimeToLive());
        assertTrue(client.getClientSettings().isRequireProofKey());
        observations.assertReleased(List.of("validator", "client-settings", "token-settings"));
        given().get("/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                .body("configured", equalTo(true));
        observations.assertReleased(List.of("discovery"));
    }

    @Test
    void addedValidatorKeepsDefaultUriChecksAndCanRejectBusinessRequests() {
        observations.clear();
        register("allowed", "https://rp.example/callback#fragment").then().statusCode(400);
        assertTrue(observations.visits.isEmpty());
        register("deny", "https://rp.example/callback")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        observations.assertReleased(List.of("validator"));
    }

    private Response register(String name, String redirect) {
        String token = UUID.randomUUID().toString();
        var client = clients.findByClientId("bootstrap");
        authorizations.save(
                OAuth2Authorization.withRegisteredClient(client)
                        .principalName(client.getClientId())
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .authorizedScopes(Set.of("client.create"))
                        .accessToken(
                                new OAuth2AccessToken(
                                        OAuth2AccessToken.TokenType.BEARER,
                                        token,
                                        Instant.now().minusSeconds(1),
                                        Instant.now().plusSeconds(300),
                                        Set.of("client.create")))
                        .build());
        return given().auth()
                .oauth2(token)
                .contentType(ContentType.JSON)
                .body(
                        Map.of(
                                "client_name",
                                name,
                                "redirect_uris",
                                List.of(redirect),
                                "grant_types",
                                List.of("authorization_code")))
                .post("/clients");
    }

    @Singleton
    public static class Config {
        @Inject
        PolicyRequestProbe request;

        @jakarta.enterprise.inject.Produces
        @Singleton
        OidcClientRegistrationRequestValidator validator(ClientRegistrationScopeValidator scopes) {
            return new OidcClientRegistrationValidator(scopes)
                    .andThen(
                            context -> {
                                request.visit("validator");
                                if ("deny"
                                        .equals(
                                                context.request()
                                                        .getClientRegistration()
                                                        .getClientName()))
                                    throw new OAuth2AuthenticationException(
                                            OAuth2ErrorCodes.INVALID_REQUEST);
                            });
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        RegistrationClientSettingsCustomizer clientSettings() {
            return settings -> {
                request.visit("client-settings");
                settings.requireProofKey(true);
            };
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        RegistrationTokenSettingsCustomizer tokenSettings() {
            return settings -> {
                request.visit("token-settings");
                settings.accessTokenTimeToLive(Duration.ofSeconds(123));
            };
        }

        @jakarta.enterprise.inject.Produces
        @Singleton
        OidcProviderMetadataCustomizer discovery() {
            return metadata -> {
                request.visit("discovery");
                metadata.claim("configured", true);
            };
        }
    }
}
