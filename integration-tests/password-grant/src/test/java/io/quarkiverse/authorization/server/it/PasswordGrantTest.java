package io.quarkiverse.authorization.server.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Set;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;

@QuarkusTest
class PasswordGrantTest {

    @Inject
    RegisteredClientRepository registeredClientRepository;

    @Inject
    OAuth2AuthorizationService authorizationService;

    @Test
    void issuesAndPersistsPasswordGrantAccessToken() {
        String accessToken = given()
                .auth().preemptive().basic("quarkus-authorization-server", "secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .formParam("scope", "message.read")
                .when().post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"))
                .body("scope", equalTo("message.read"))
                .extract().path("access_token");

        assertInstanceOf(JdbcRegisteredClientRepository.class, this.registeredClientRepository);
        assertInstanceOf(JdbcOAuth2AuthorizationService.class, this.authorizationService);
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                accessToken, OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(authorization);
        assertEquals("resource-owner", authorization.getPrincipalName());
        assertEquals(Set.of("message.read"), authorization.getAuthorizedScopes());

        given().when().get("/.well-known/oauth-authorization-server").then()
                .statusCode(200)
                .body("grant_types_supported", hasItem("password"));
    }
}
