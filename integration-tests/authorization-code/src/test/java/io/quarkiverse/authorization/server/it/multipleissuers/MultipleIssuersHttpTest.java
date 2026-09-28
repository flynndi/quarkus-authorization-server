package io.quarkiverse.authorization.server.it.multipleissuers;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;

@QuarkusTest
@TestProfile(MultipleIssuersProfile.class)
public class MultipleIssuersHttpTest {
    static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    static final String REDIRECT = "https://client.example/callback";

    @Test
    public void clientCredentialsInteroperateWithTheMatchingOidcResourceTenant() {
        for (String tenant : List.of("alpha", "beta")) {
            String token = MultipleIssuersHttpTest.request().auth().preemptive().basic("shared", tenant + "-secret")
                    .formParam("grant_type", "client_credentials")
                    .formParam("scope", tenant).post("/" + tenant + "/token").then().statusCode(200).extract()
                    .path("access_token");
            MultipleIssuersHttpTest.request().auth().oauth2(token).get("/" + tenant + "/message").then().statusCode(200)
                    .body("tenant", equalTo(tenant)).body("subject", equalTo("shared"));
            String other = tenant.equals("alpha") ? "beta" : "alpha";
            MultipleIssuersHttpTest.request().auth().oauth2(token).get("/" + other + "/message").then().statusCode(401);
            MultipleIssuersHttpTest.request().auth().preemptive().basic("shared", other + "-secret").formParam("token", token)
                    .post("/" + other + "/oauth2/introspect").then().statusCode(200).body("active", equalTo(false));
            MultipleIssuersHttpTest.request().basePath("").get("/.well-known/oauth-authorization-server/server/" + tenant)
                    .then().statusCode(200)
                    .body("issuer", endsWith("/server/" + tenant))
                    .body("token_endpoint", endsWith("/server/" + tenant + "/token"));
        }
    }

    @Test
    public void jdbcAuthorizationAndRefreshAreIsolatedAcrossIssuers() {
        var cookies = MultipleIssuersHttpTest.request().redirects().follow(false).formParam("j_username", "alice")
                .formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302).extract().cookies();
        for (String tenant : List.of("alpha", "beta")) {
            var authorization = MultipleIssuersHttpTest.request().redirects().follow(false).cookies(cookies)
                    .queryParam("response_type", "code")
                    .queryParam("client_id", "shared").queryParam("redirect_uri", REDIRECT)
                    .queryParam("scope", "openid " + tenant)
                    .queryParam("code_challenge", CHALLENGE).queryParam("code_challenge_method", "S256")
                    .get("/" + tenant + "/authorize");
            if (authorization.statusCode() == 200) {
                String state = authorization.htmlPath().getString("**.find { it.@name == 'state' }.@value");
                authorization = MultipleIssuersHttpTest.request().redirects().follow(false).cookies(cookies)
                        .formParam("client_id", "shared")
                        .formParam("state", state).formParam("scope", tenant).formParam("consent_action", "approve")
                        .post("/" + tenant + "/authorize");
            }
            authorization.then().statusCode(302);
            String code = MultipleIssuersHttpTest.query(authorization.header("Location"), "code");
            String other = tenant.equals("alpha") ? "beta" : "alpha";
            MultipleIssuersHttpTest.request().auth().preemptive().basic("shared", other + "-secret")
                    .formParam("grant_type", "authorization_code")
                    .formParam("code", code).formParam("redirect_uri", REDIRECT).formParam("code_verifier", VERIFIER)
                    .post("/" + other + "/token").then().statusCode(400).body("error", equalTo("invalid_grant"));
            var tokens = MultipleIssuersHttpTest.request().auth().preemptive().basic("shared", tenant + "-secret")
                    .formParam("grant_type", "authorization_code")
                    .formParam("code", code).formParam("redirect_uri", REDIRECT).formParam("code_verifier", VERIFIER)
                    .post("/" + tenant + "/token").then().statusCode(200).extract().response();
            String access = tokens.path("access_token"), refresh = tokens.path("refresh_token");
            assertNotNull(tokens.path("id_token"));
            MultipleIssuersHttpTest.request().auth().oauth2(access).get("/" + tenant + "/message").then().statusCode(200).body(
                    "subject",
                    equalTo("alice"));
            MultipleIssuersHttpTest.request().auth().oauth2(access).get("/" + other + "/userinfo").then().statusCode(401);
            MultipleIssuersHttpTest.request().auth().preemptive().basic("shared", other + "-secret")
                    .formParam("grant_type", "refresh_token")
                    .formParam("refresh_token", refresh).post("/" + other + "/token").then().statusCode(400);
            MultipleIssuersHttpTest.request().auth().preemptive().basic("shared", tenant + "-secret")
                    .formParam("grant_type", "refresh_token")
                    .formParam("refresh_token", refresh).post("/" + tenant + "/token").then().statusCode(200);
        }
    }

    static RequestSpecification request() {
        // Keep the same root for in-process and packaged HTTP tests.
        return RestAssured.given().basePath("/server");
    }

    static String query(String location, String name) {
        return java.util.Arrays.stream(java.net.URI.create(location).getRawQuery().split("&")).map(value -> value.split("=", 2))
                .filter(parts -> name.equals(parts[0]))
                .map(parts -> java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8))
                .findFirst().orElseThrow();
    }
}
