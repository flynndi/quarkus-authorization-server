package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.response.Response;

class OidcLogoutEndpointTest {
    private static final String REDIRECT = "https://client.example/callback";
    private static final String POST_LOGOUT = "https://client.example/bye?existing=1";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withApplicationRoot(jar -> jar
            .addClasses(LogoutTestApplication.class, LogoutTestApplication.PasswordProvider.class,
                    LogoutTestApplication.TrustedProvider.class)
            .addAsResource(new StringAsset("""
                    quarkus.http.root-path=/api
                    quarkus.http.auth.form.enabled=true
                    quarkus.http.auth.form.cookie-name=login
                    quarkus.http.auth.form.cookie-path=/api
                    quarkus.http.auth.form.landing-page=
                    quarkus.http.auth.form.error-page=
                    quarkus.http.auth.form.login-page=/api/login
                    quarkus.http.auth.form.new-cookie-interval=0S
                    quarkus.http.auth.session.encryption-key=oidc-logout-test-encryption-key
                    quarkus.authorization-server.issuer=http://localhost:8081/api
                    quarkus.authorization-server.oidc.enabled=true
                    quarkus.authorization-server.oidc-logout-endpoint=/bye
                    quarkus.authorization-server.clients.client.client-secret=%s
                    quarkus.authorization-server.clients.client.authorization-grant-types=authorization_code,refresh_token
                    quarkus.authorization-server.clients.client.redirect-uris=https://client.example/callback
                    quarkus.authorization-server.clients.client.post-logout-redirect-uris=https://client.example/bye?existing=1
                    quarkus.authorization-server.clients.client.scopes=openid,profile
                    """.formatted(io.quarkus.elytron.security.common.BcryptUtil.bcryptHash("secret"))),
                    "application.properties"));

    @Test
    void formLoginCodeRefreshUserInfoLogoutAndLoginAgain() {
        long before = Instant.now().getEpochSecond();
        Map<String, String> cookies = login("alice");
        assertNotNull(cookies.get("login.oidc"));
        Response tokens = tokens(cookies);
        Map<String, Object> id = claims(tokens.path("id_token"));
        assertTrue(((Number) id.get("auth_time")).longValue() >= before);
        assertTrue(((Number) id.get("auth_time")).longValue() <= Instant.now().getEpochSecond());
        assertNotNull(id.get("sid"));
        assertNotEquals(cookies.get("login.oidc"), id.get("sid"));
        assertNotEquals(cookies.get("login"), id.get("sid"));
        assertEquals("request-nonce", id.get("nonce"));

        given().header("Authorization", "Bearer " + tokens.<String> path("access_token")).get("/userinfo")
                .then().statusCode(200).body("sub", equalTo("alice"));
        Response refreshed = given().auth().preemptive().basic("client", "secret")
                .contentType("application/x-www-form-urlencoded").formParam("grant_type", "refresh_token")
                .formParam("refresh_token", tokens.<String> path("refresh_token")).post("/oauth2/token")
                .then().statusCode(200).extract().response();
        Map<String, Object> newId = claims(refreshed.path("id_token"));
        assertEquals(id.get("sid"), newId.get("sid"));
        assertEquals(id.get("auth_time"), newId.get("auth_time"));
        assertFalse(newId.containsKey("nonce"));

        Response logout = given().cookies(cookies).redirects().follow(false)
                .contentType("application/x-www-form-urlencoded")
                .formParam("id_token_hint", refreshed.<String> path("id_token"))
                .formParam("client_id", "client").formParam("post_logout_redirect_uri", POST_LOGOUT)
                .formParam("state", "state +&").post("/bye").then().statusCode(302)
                .header("Location", equalTo(POST_LOGOUT + "&state=state+%2B%26")).extract().response();
        assertEquals(0, logout.getDetailedCookie("login").getMaxAge());
        assertEquals(0, logout.getDetailedCookie("login.oidc").getMaxAge());
        assertEquals("/api", logout.getDetailedCookie("login.oidc").getPath());
        given().redirects().follow(false).queryParams(Map.of("response_type", "code", "client_id", "client",
                "redirect_uri", REDIRECT, "scope", "openid", "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method", "S256")).get("/oauth2/authorize")
                .then().statusCode(302).header("Location", containsString("/api/login"));
        // Ending the browser session does not revoke issued access tokens.
        given().header("Authorization", "Bearer " + refreshed.<String> path("access_token")).get("/userinfo")
                .then().statusCode(200);
        assertNotEquals(id.get("sid"), claims(tokens(login("alice")).path("id_token")).get("sid"));
    }

    @Test
    void sameLoginKeepsSidAndAuthenticationTimeButAnotherLoginCannotUseItsHint() {
        Map<String, String> first = login("alice");
        Response firstTokens = tokens(first);
        Map<String, Object> firstClaims = claims(firstTokens.path("id_token"));
        Map<String, Object> secondClaims = claims(tokens(first).path("id_token"));
        assertEquals(firstClaims.get("sid"), secondClaims.get("sid"));
        assertEquals(firstClaims.get("auth_time"), secondClaims.get("auth_time"));
        for (Map<String, String> other : java.util.List.of(login("alice"), login("bob"))) {
            given().cookies(other).redirects().follow(false)
                    .queryParam("id_token_hint", firstTokens.<String> path("id_token")).get("/bye")
                    .then().statusCode(400).body("error", equalTo("invalid_token"));
        }
    }

    @Test
    void metadataAnonymousHintAndParameterFailures() {
        given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("end_session_endpoint", equalTo("http://localhost:8081/api/bye"));
        String hint = tokens(login("alice")).path("id_token");
        given().redirects().follow(false).queryParam("id_token_hint", hint)
                .queryParam("post_logout_redirect_uri", POST_LOGOUT).get("/bye")
                .then().statusCode(302).header("Location", equalTo(POST_LOGOUT));
        given().redirects().follow(false).queryParam("id_token_hint", hint).get("/bye")
                .then().statusCode(302).header("Location", equalTo("/"));
        given().get("/bye").then().statusCode(400).body("error", equalTo("invalid_request"));
        given().queryParam("id_token_hint", hint, hint).get("/bye")
                .then().statusCode(400).body("error", equalTo("invalid_request"));
        given().queryParam("id_token_hint", hint).queryParam("client_id", "", "client").get("/bye")
                .then().statusCode(400).body("error", equalTo("invalid_request"));
        given().queryParam("id_token_hint", hint).queryParam("client_id", "other").get("/bye")
                .then().statusCode(400).body("error", equalTo("invalid_request"));
        given().queryParam("id_token_hint", hint).queryParam("post_logout_redirect_uri", "https://evil.example").get("/bye")
                .then().statusCode(400).body("error", equalTo("invalid_request"));
        given().queryParam("id_token_hint", "tampered").get("/bye")
                .then().statusCode(400).body("error", equalTo("invalid_token"));
        given().contentType("application/json").body("{}").post("/bye").then().statusCode(415);
        given().put("/bye").then().statusCode(404);
        given().get("/connect/logout").then().statusCode(404);
    }

    @Test
    void missingOrTamperedMetadataDoesNotInventAuthenticationTimeOrAuthenticateUser() {
        Map<String, String> cookies = login("alice");
        given().cookie("login.oidc", cookies.get("login.oidc")).redirects().follow(false)
                .queryParams(
                        Map.of("response_type", "code", "client_id", "client", "redirect_uri", REDIRECT, "scope", "openid"))
                .get("/oauth2/authorize").then().statusCode(302);
        cookies.remove("login.oidc");
        Map<String, Object> claims = claims(tokens(cookies).path("id_token"));
        assertFalse(claims.containsKey("auth_time"));
        assertFalse(claims.containsKey("sid"));
        cookies.put("login.oidc", "tampered");
        assertFalse(claims(tokens(cookies).path("id_token")).containsKey("auth_time"));
        given().contentType("application/x-www-form-urlencoded").formParam("j_username", "alice")
                .formParam("j_password", "wrong").post("/j_security_check")
                .then().statusCode(401);
    }

    static Map<String, String> login(String username) {
        return new LinkedHashMap<>(given().contentType("application/x-www-form-urlencoded").formParam("j_username", username)
                .formParam("j_password", "password").post("/j_security_check")
                .then().statusCode(200).extract().cookies());
    }

    static Response tokens(Map<String, String> cookies) {
        Response response = given().cookies(cookies).redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", "client")
                .queryParam("redirect_uri", REDIRECT).queryParam("scope", "openid profile")
                .queryParam("nonce", "request-nonce").queryParam("code_challenge", CHALLENGE)
                .queryParam("code_challenge_method", "S256").get("/oauth2/authorize")
                .then().statusCode(302).extract().response();
        String query = URI.create(response.header("Location")).getRawQuery();
        String code = java.util.Arrays.stream(query.split("&")).filter(value -> value.startsWith("code="))
                .map(value -> URLDecoder.decode(value.substring(5), StandardCharsets.UTF_8)).findFirst().orElseThrow();
        return given().auth().preemptive().basic("client", "secret").contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code").formParam("code", code).formParam("redirect_uri", REDIRECT)
                .formParam("code_verifier", VERIFIER).post("/oauth2/token").then().statusCode(200).extract().response();
    }

    static Map<String, Object> claims(String jwt) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(
                    java.util.Base64.getUrlDecoder().decode(jwt.split("\\.")[1]),
                    new com.fasterxml.jackson.core.type.TypeReference<>() {
                    });
        } catch (java.io.IOException exception) {
            throw new AssertionError(exception);
        }
    }

}
