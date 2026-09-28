package io.quarkiverse.authorization.server.it.authorizationcode;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;

/** Black-box browser flow: no CDI, database internals or in-process authorization-server objects. */
@QuarkusTest
public class OidcBrowserFlowTest {
    private static final String REDIRECT = "http://localhost:5173/callback";
    private static final String PUBLIC = "authorization-code-public-client";
    private static final String CONFIDENTIAL = "authorization-code-confidential-client";
    private static final String SECRET = "authorization-code-client-secret";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    void publicPkceAndConfidentialRefreshCompleteOidcBrowserFlow() throws Exception {
        Map<String, Object> discovery = given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("end_session_endpoint", endsWith("/connect/logout"))
                .body("userinfo_endpoint", endsWith("/userinfo")).extract().jsonPath().getMap("$");
        for (String client : List.of(PUBLIC, CONFIDENTIAL)) {
            Map<String, String> cookies = new LinkedHashMap<>(given().redirects().follow(false)
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                    .post("/j_security_check").then().statusCode(302).extract().cookies());
            assertNotNull(cookies.get("quarkus-credential"));
            assertNotNull(cookies.get("quarkus-credential.oidc"));
            Response authorization = given().cookies(cookies).redirects().follow(false)
                    .queryParam("response_type", "code").queryParam("client_id", client)
                    .queryParam("redirect_uri", REDIRECT).queryParam("scope", "openid profile message.read")
                    .queryParam("state", "rp-state").queryParam("nonce", "rp-nonce")
                    .queryParam("code_challenge", CHALLENGE).queryParam("code_challenge_method", "S256")
                    .get("/oauth2/authorize");
            if (authorization.statusCode() == 200) {
                assertTrue(authorization.contentType().startsWith("text/html"));
                String consentState = authorization.htmlPath().getString("**.find { it.@name == 'state' }.@value");
                assertEquals(client, authorization.htmlPath().getString("**.find { it.@name == 'client_id' }.@value"));
                authorization = given().cookies(cookies).redirects().follow(false)
                        .contentType("application/x-www-form-urlencoded").formParam("client_id", client)
                        .formParam("state", consentState).formParam("scope", "profile", "message.read")
                        .post("/oauth2/authorize");
            }
            assertEquals(302, authorization.statusCode());
            Map<String, String> query = query(authorization.header("Location"));
            assertEquals("rp-state", query.get("state"));
            var exchange = given().contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "authorization_code").formParam("code", query.get("code"))
                    .formParam("redirect_uri", REDIRECT).formParam("code_verifier", VERIFIER);
            if (client.equals(PUBLIC)) {
                exchange.formParam("client_id", client);
            } else {
                exchange.auth().preemptive().basic(client, SECRET);
            }
            Response tokens = exchange.post("/oauth2/token").then().statusCode(200).extract().response();
            String hint = tokens.path("id_token");
            Map<String, Object> idToken = claimsAndVerify(hint);
            assertEquals(discovery.get("issuer"), idToken.get("iss"));
            assertEquals("rp-nonce", idToken.get("nonce"));
            assertEquals(List.of(client), idToken.get("aud"));
            assertNotNull(idToken.get("sid"));
            assertNotNull(idToken.get("auth_time"));
            assertEquals("resource-owner", idToken.get("sub"));

            String accessToken = tokens.path("access_token");
            if (client.equals(CONFIDENTIAL)) {
                tokens = given().auth().preemptive().basic(client, SECRET).contentType("application/x-www-form-urlencoded")
                        .formParam("grant_type", "refresh_token")
                        .formParam("refresh_token", tokens.<String> path("refresh_token"))
                        .formParam("scope", "openid").post("/oauth2/token").then().statusCode(200).extract().response();
                hint = tokens.path("id_token");
                accessToken = tokens.path("access_token");
                Map<String, Object> refreshed = claimsAndVerify(hint);
                assertEquals(idToken.get("sid"), refreshed.get("sid"));
                assertEquals(idToken.get("auth_time"), refreshed.get("auth_time"));
                assertFalse(refreshed.containsKey("nonce"));
            } else {
                assertNull(tokens.path("refresh_token"));
            }
            given().header("Authorization", "Bearer " + accessToken).get("/userinfo")
                    .then().statusCode(200).body("sub", equalTo(idToken.get("sub")))
                    .body("$", not(hasKey("sid"))).body("$", not(hasKey("auth_time")));
            Response logout = given().cookies(cookies).redirects().follow(false)
                    .contentType("application/x-www-form-urlencoded").formParam("id_token_hint", hint)
                    .formParam("client_id", client).formParam("post_logout_redirect_uri", "http://localhost:5173/")
                    .formParam("state", "logout-state").post("/connect/logout")
                    .then().statusCode(302).header("Location", equalTo("http://localhost:5173/?state=logout-state"))
                    .extract().response();
            assertEquals(0, logout.getDetailedCookie("quarkus-credential").getMaxAge());
            assertEquals(0, logout.getDetailedCookie("quarkus-credential.oidc").getMaxAge());
            given().redirects().follow(false)
                    .queryParam("response_type", "code").queryParam("client_id", client)
                    .queryParam("redirect_uri", REDIRECT).queryParam("scope", "openid")
                    .queryParam("code_challenge", CHALLENGE).queryParam("code_challenge_method", "S256")
                    .get("/oauth2/authorize").then().statusCode(302)
                    .header("Location", containsString("/login"));
        }
    }

    private static Map<String, Object> claimsAndVerify(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        Map<String, Object> header = new JsonPath(new String(Base64.getUrlDecoder().decode(parts[0]),
                StandardCharsets.UTF_8)).getMap("$");
        List<Map<String, String>> keys = given().get("/oauth2/jwks").then().statusCode(200).extract().path("keys");
        Map<String, String> key = keys.stream().filter(k -> k.get("kid").equals(header.get("kid"))).findFirst().orElseThrow();
        var publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                new BigInteger(1, Base64.getUrlDecoder().decode(key.get("n"))),
                new BigInteger(1, Base64.getUrlDecoder().decode(key.get("e")))));
        assertEquals("RS256", header.get("alg"));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(signature.verify(Base64.getUrlDecoder().decode(parts[2])));
        return new JsonPath(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)).getMap("$");
    }

    private static Map<String, String> query(String uri) {
        Map<String, String> parameters = new LinkedHashMap<>();
        for (String part : URI.create(uri).getRawQuery().split("&")) {
            String[] pair = part.split("=", 2);
            parameters.put(pair[0], URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
        }
        return parameters;
    }
}
