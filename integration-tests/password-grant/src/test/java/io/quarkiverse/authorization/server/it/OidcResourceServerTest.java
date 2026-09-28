package io.quarkiverse.authorization.server.it;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;

/** Real Quarkus OIDC discovery and bearer verification, not direct JWKS or a mocked security identity. */
@QuarkusTest
public class OidcResourceServerTest {
    @Test
    void passwordAccessTokenWorksThroughDiscoveryAndUserInfo() {
        given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("userinfo_endpoint", endsWith("/userinfo"))
                .body("id_token_signing_alg_values_supported", hasItem("RS256"));
        Response tokens = given().auth().preemptive().basic("quarkus-authorization-server", "secret")
                .contentType("application/x-www-form-urlencoded").formParam("grant_type", "password")
                .formParam("username", "resource-owner").formParam("password", "resource-owner-password")
                .formParam("scope", "openid profile message.read").post("/oauth2/token")
                .then().statusCode(200).body("id_token", notNullValue()).extract().response();
        String token = tokens.path("access_token");
        given().header("Authorization", "Bearer " + token).get("/api/resource").then().statusCode(200)
                .body("subject", equalTo("resource-owner")).body("audience", hasItem("quarkus-authorization-server"));
        given().header("Authorization", "Bearer " + token).get("/userinfo").then().statusCode(200)
                .body("sub", equalTo("resource-owner"));
        given().header("Authorization", "Bearer " + token + "tampered").get("/api/resource").then().statusCode(401);
        given().get("/api/resource").then().statusCode(401);
    }
}
