package io.quarkiverse.authorization.server.it.oidc;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.support.OAuthRequests;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;

@QuarkusTest
public class ResourceServerTest {

    @Test
    void discoveryPublishesTheIssuerAndSigningKeys() {
        var metadata = RestAssured.get("/.well-known/openid-configuration")
                .then().statusCode(200).body("authorization_endpoint", notNullValue())
                .body("token_endpoint", notNullValue()).body("grant_types_supported", hasItem("authorization_code"))
                .extract().response();
        String token = OAuthRequests.userTokens("jsonWebToken").path("access_token");
        RestAssured.given().auth().oauth2(token).get("/api/resource/jsonWebToken")
                .then().statusCode(200).body("issuer", equalTo(metadata.<String> path("issuer")));
        RestAssured.get(metadata.<String> path("jwks_uri")).then().statusCode(200).body("keys[0].kid", notNullValue());
    }

    @Test
    void bothResourceEndpointsRequireBearerAuthentication() {
        for (String endpoint : new String[] { "securityIdentity", "jsonWebToken" }) {
            RestAssured.get("/api/resource/" + endpoint).then().statusCode(401);
            RestAssured.given().auth().oauth2("invalid-token").get("/api/resource/" + endpoint)
                    .then().statusCode(401);
        }
    }

    @Test
    void formLoginCookieCannotAuthenticateResourceRequests() {
        var cookies = OAuthRequests.login();
        for (String endpoint : new String[] { "securityIdentity", "jsonWebToken" }) {
            RestAssured.given().cookies(cookies).redirects().follow(false).get("/api/resource/" + endpoint)
                    .then().statusCode(401);
        }
    }

    @Test
    void userRolesDoNotReplaceTheMissingTokenScope() {
        String token = OAuthRequests.userTokens("jsonWebToken").path("access_token");
        RestAssured.given().auth().oauth2(token).get("/api/resource/jsonWebToken")
                .then().statusCode(200).body("groups", hasItem("admin"));
        RestAssured.given().auth().oauth2(token).get("/api/resource/securityIdentity").then().statusCode(403);
    }

}
