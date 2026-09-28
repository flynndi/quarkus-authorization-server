package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;

class OidcClientRegistrationDefaultsTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(ClientRegistrationTestApplication::baseApplication);

    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    RegisteredClientRepository clients;

    @Test
    void independentOAuthRegistrationIsNotInstalledByDefault() {
        given().contentType(ContentType.JSON).body("{}").post("/oauth2/register").then().statusCode(404);
        given().get("/.well-known/oauth-authorization-server").then().statusCode(200)
                .body("$", org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasKey("registration_endpoint")));
        org.junit.jupiter.api.Assertions.assertFalse(io.quarkus.arc.Arc.container()
                .instance(io.quarkiverse.authorization.server.runtime.client.registration.OAuth2ClientRegistrationService.class)
                .isAvailable());
    }

    @Test
    void defaultRegistrationRejectsRequestedScopesBeforeAnyStorageWrite() {
        String initial = initial();
        given().auth().oauth2(initial).contentType(ContentType.JSON)
                .body(Map.of("redirect_uris", List.of("https://rp.example/callback"), "scope", "openid"))
                .post("/clients").then().statusCode(400).body("error", equalTo("invalid_scope"));
        assertTrue(this.authorizations.findByToken(initial, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
        given().auth().oauth2(initial).contentType(ContentType.JSON)
                .body(Map.of("redirect_uris", List.of("https://rp.example/callback")))
                .post("/clients").then().statusCode(201);
    }

    @Test
    void defaultRegistrationRejectsRelativeAndUnsafeUris() {
        String initial = initial();
        for (String uri : List.of("//rp.example/callback", "javascript:alert(1)", "data:text/html,hello")) {
            given().auth().oauth2(initial).contentType(ContentType.JSON).body(Map.of("redirect_uris", List.of(uri)))
                    .post("/clients").then().statusCode(400).body("error", equalTo("invalid_redirect_uri"));
        }
        assertTrue(this.authorizations.findByToken(initial, OAuth2TokenType.ACCESS_TOKEN).getAccessToken().isActive());
    }

    private String initial() {
        String value = UUID.randomUUID().toString();
        var client = this.clients.findByClientId("bootstrap");
        this.authorizations.save(OAuth2Authorization.withRegisteredClient(client).principalName(client.getClientId())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).authorizedScopes(Set.of("client.create"))
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, value,
                        Instant.now().minusSeconds(1), Instant.now().plusSeconds(300), Set.of("client.create")))
                .build());
        return value;
    }
}
