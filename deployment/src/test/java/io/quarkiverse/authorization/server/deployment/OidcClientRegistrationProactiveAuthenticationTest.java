package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import java.time.Instant;
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
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.http.Headers;

class OidcClientRegistrationProactiveAuthenticationTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(ClientRegistrationTestApplication::application)
            .overrideConfigKey("quarkus.http.auth.proactive", "true");

    @Inject
    OAuth2AuthorizationService service;
    @Inject
    RegisteredClientRepository clients;

    @Test
    void preservesEndpointChallengesWithProactiveAuthentication() {
        given().get("/clients").then().statusCode(401).header("WWW-Authenticate", equalTo("Bearer"));
        given().header("Authorization", "Bearer unknown").get("/clients").then().statusCode(401)
                .contentType(ContentType.JSON).body("error", equalTo("invalid_token"));
        given().headers(new Headers(new Header("Authorization", "Bearer first"), new Header("Authorization", "Bearer second")))
                .get("/clients").then().statusCode(400).body("error", equalTo("invalid_request"));
        given().header("Authorization", "Bearer unknown").get("/other").then().statusCode(200).body(equalTo("unaffected"));
    }

    @Test
    void registersAndReadsWithProactiveAuthentication() {
        String initial = UUID.randomUUID().toString();
        this.service.save(OAuth2Authorization.withRegisteredClient(this.clients.findByClientId("bootstrap"))
                .principalName("bootstrap").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(Set.of("client.create"))
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, initial,
                        Instant.now(), Instant.now().plusSeconds(300), Set.of("client.create")))
                .build());
        var registration = given().header("Authorization", "Bearer " + initial).contentType(ContentType.JSON)
                .body("{\"redirect_uris\":[\"https://rp.example/callback\"]}").post("/clients")
                .then().statusCode(201).extract().response();
        given().header("Authorization", "Bearer " + registration.<String> path("registration_access_token"))
                .queryParam("client_id", registration.<String> path("client_id")).get("/clients")
                .then().statusCode(200).body("client_id", equalTo(registration.path("client_id")));
        given().header("Authorization", "Bearer " + initial).contentType(ContentType.JSON)
                .body("{\"redirect_uris\":[\"https://rp.example/callback\"]}").post("/clients")
                .then().statusCode(401).body("error", equalTo("invalid_token"));
    }
}
