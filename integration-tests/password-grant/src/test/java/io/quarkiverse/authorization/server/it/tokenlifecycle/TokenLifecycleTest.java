package io.quarkiverse.authorization.server.it.tokenlifecycle;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** HTTP-only lifecycle contract, reused unchanged against the packaged JVM application. */
@QuarkusTest
public class TokenLifecycleTest {

    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Pattern CONSENT_STATE = Pattern.compile("name=\"state\" value=\"([^\"]+)\"");

    @Test
    void passwordAndRefreshKeepReferenceAccessTokensAndJwtIdTokens() {
        Response password = client("password-client", "password-secret").contentType(ContentType.URLENC)
                .formParam("grant_type", "password").formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .formParam("scope", "openid profile message.read").post("/oauth2/token")
                .then().statusCode(200).body("refresh_token", notNullValue()).body("id_token", notNullValue())
                .extract().response();
        String access = password.path("access_token");
        assertOpaque(access);
        assertJwt(password.path("id_token"));
        resource(access).then().statusCode(200).body("subject", equalTo("resource-owner"))
                .body("introspection_client_id", equalTo("password-client"));
        userInfo(access).then().statusCode(200).body("sub", equalTo("resource-owner"));

        Response refreshed = client("password-client", "password-secret").contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", password.<String> path("refresh_token"))
                .post("/oauth2/token").then().statusCode(200)
                .body("id_token", notNullValue()).extract().response();
        assertOpaque(refreshed.path("access_token"));
        assertJwt(refreshed.path("id_token"));
        resource(refreshed.path("access_token")).then().statusCode(200)
                .body("subject", equalTo("resource-owner"));
        userInfo(refreshed.path("access_token")).then().statusCode(200)
                .body("sub", equalTo("resource-owner"));
    }

    static String clientCredentials(String clientId, String secret) {
        return client(clientId, secret).contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials").formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200).extract().path("access_token");
    }

    static Response introspect(String token) {
        return client("resource-server", "resource-secret").contentType(ContentType.URLENC)
                .formParam("token", token).post("/oauth2/introspect");
    }

    static Response revoke(String clientId, String secret, String token) {
        return client(clientId, secret).contentType(ContentType.URLENC)
                .formParam("token", token).post("/oauth2/revoke");
    }

    static Response resource(String token) {
        return given().header("Authorization", "Bearer " + token).get("/lifecycle/messages");
    }

    private static Response userInfo(String token) {
        return given().header("Authorization", "Bearer " + token).get("/userinfo");
    }

    private static RequestSpecification client(String clientId, String secret) {
        return given().auth().preemptive().basic(clientId, secret);
    }

    private static Map<String, String> login() {
        return given().redirects().follow(false).contentType(ContentType.URLENC)
                .formParam("j_username", TokenLifecycleServerConfig.RESOURCE_OWNER)
                .formParam("j_password", TokenLifecycleServerConfig.RESOURCE_OWNER_PASSWORD)
                .post("/j_security_check").then().statusCode(302).extract().cookies();
    }

    private static String authorize(String clientId, String redirectUri, Map<String, String> cookies) {
        Response authorization = given().cookies(cookies).redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri).queryParam("scope", "openid message.read")
                .queryParam("state", "client-state").queryParam("nonce", "token-lifecycle-nonce")
                .queryParam("code_challenge", CHALLENGE).queryParam("code_challenge_method", "S256")
                .get("/oauth2/authorize");
        if (authorization.statusCode() == 200) {
            var matcher = CONSENT_STATE.matcher(authorization.asString());
            assertTrue(matcher.find(), "Missing consent state");
            authorization = given().cookies(cookies).redirects().follow(false).contentType(ContentType.URLENC)
                    .formParam("client_id", clientId).formParam("state", matcher.group(1))
                    .formParam("scope", "message.read").post("/oauth2/authorize");
        }
        assertEquals(302, authorization.statusCode());
        Map<String, String> parameters = queryParameters(authorization.header("Location"));
        assertEquals("client-state", parameters.get("state"));
        assertNotNull(parameters.get("code"));
        return parameters.get("code");
    }

    private static Response exchange(String clientId, String secret, String redirectUri, String code) {
        return client(clientId, secret).contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code").formParam("code", code)
                .formParam("redirect_uri", redirectUri).formParam("code_verifier", VERIFIER)
                .post("/oauth2/token").then().statusCode(200).body("id_token", notNullValue())
                .extract().response();
    }

    private static Map<String, String> queryParameters(String location) {
        Map<String, String> parameters = new LinkedHashMap<>();
        for (String part : URI.create(location).getRawQuery().split("&")) {
            String[] pair = part.split("=", 2);
            parameters.put(pair[0], URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8));
        }
        return parameters;
    }

    private static void assertOpaque(String token) {
        assertNotNull(token);
        assertFalse(token.contains("."), "Reference access tokens must not be JWTs");
    }

    private static void assertJwt(String token) {
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);
    }
}
