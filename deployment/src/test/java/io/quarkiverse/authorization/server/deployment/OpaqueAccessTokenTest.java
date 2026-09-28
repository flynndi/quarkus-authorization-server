package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;

class OpaqueAccessTokenTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withApplicationRoot(jar -> jar.addAsResource(
            new StringAsset("""
                    quarkus:
                      authorization-server:
                        issuer: https://issuer.example
                        clients:
                          opaque-client:
                            client-secret: $2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                            authorization-grant-types: client_credentials
                            scopes: message.read
                            access-token-time-to-live: PT3M
                            access-token-format: reference
                    """), "application.yml"));

    @Inject
    OAuth2AuthorizationService authorizations;

    @Test
    void yamlClientUsesDefaultOpaqueGeneratorAndPersistsClaims() {
        String token = given().auth().preemptive().basic("opaque-client", "client-secret")
                .contentType(ContentType.URLENC).formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read").post("/oauth2/token").then().statusCode(200)
                .extract().path("access_token");

        assertEquals(128, token.length());
        assertFalse(token.contains("."));
        var authorization = this.authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        assertEquals("opaque-client", authorization.getPrincipalName());
        assertEquals("opaque-client", authorization.getAccessToken().getClaims().get("sub"));
        assertEquals(java.time.Duration.ofMinutes(3), java.time.Duration.between(
                authorization.getAccessToken().getToken().getIssuedAt(),
                authorization.getAccessToken().getToken().getExpiresAt()));
    }
}
