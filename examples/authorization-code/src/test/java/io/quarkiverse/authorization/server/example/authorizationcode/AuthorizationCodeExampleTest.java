package io.quarkiverse.authorization.server.example.authorizationcode;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;

/** Exercises the documented happy path against this example's own application. */
@QuarkusTest
public class AuthorizationCodeExampleTest {
    @Test
    void completesDocumentedFlow() {
        var cookies = RestAssured.given().redirects().follow(false)
                .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(302).extract().cookies();
        var page = RestAssured.given().cookies(cookies).redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", "authorization-code-public-client")
                .queryParam("redirect_uri", "http://localhost:5173/callback").queryParam("scope", "openid message.read")
                .queryParam("state", "example-state")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256")
                .get("/oauth2/authorize").then().statusCode(200).extract().response();
        String consent = page.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        String redirect = RestAssured.given().cookies(cookies).redirects().follow(false)
                .formParam("client_id", "authorization-code-public-client").formParam("state", consent)
                .formParam("scope", "message.read").formParam("consent_action", "approve")
                .post("/oauth2/authorize").then().statusCode(302).extract().header("Location");
        String code = java.util.Arrays.stream(java.net.URI.create(redirect).getRawQuery().split("&"))
                .filter(value -> value.startsWith("code="))
                .map(value -> java.net.URLDecoder.decode(value.substring(5), java.nio.charset.StandardCharsets.UTF_8))
                .findFirst().orElseThrow();
        String access = RestAssured.given().formParam("client_id", "authorization-code-public-client")
                .formParam("grant_type", "authorization_code").formParam("code", code)
                .formParam("redirect_uri", "http://localhost:5173/callback")
                .formParam("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                .post("/oauth2/token").then().statusCode(200).body("id_token", notNullValue())
                .extract().path("access_token");
        RestAssured.given().auth().oauth2(access).get("/api/messages").then().statusCode(200)
                .body("subject", equalTo("resource-owner"));
    }
}
