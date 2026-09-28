package io.quarkiverse.authorization.server.it.authorizationcode;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;

/** Exercises the demo's credential boundaries through HTTP, including actual OIDC resource validation. */
@QuarkusTest
public class BrowserAuthenticationTest {
    private static final String COOKIE = "quarkus-credential";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @Test
    void formPreservesTheAuthorizationRequestAcrossLoginFailureAndResumesItAfterSuccess() {
        Response challenge = RestAssured.given().redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", "authorization-code-confidential-client")
                .queryParam("redirect_uri", "http://localhost:5173/callback").queryParam("scope", "openid profile")
                .queryParam("state", "native-form-navigation")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256").get("/oauth2/authorize")
                .then().statusCode(302).header("Location", Matchers.endsWith("/auth/login")).extract().response();
        String savedRequest = challenge.cookie("quarkus-redirect-location");
        Assertions.assertNotNull(savedRequest);
        Response page = RestAssured.given().cookies(challenge.cookies()).redirects().follow(false)
                .get("/auth/login").then().statusCode(200)
                .contentType("text/html").header("Cache-Control", "no-store")
                .body(Matchers.containsString("action=\"/j_security_check\"")).extract().response();
        Assertions.assertNull(page.cookie("quarkus-redirect-location"));

        RestAssured.given().cookies(challenge.cookies()).redirects().follow(false)
                .contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "resource-owner").formParam("j_password", "incorrect")
                .post("/j_security_check").then().statusCode(302)
                .header("Location", Matchers.endsWith("/auth/login?error=true"));
        RestAssured.given().cookies(challenge.cookies()).redirects().follow(false)
                .get("/auth/login?error=true").then().statusCode(200)
                .body(Matchers.containsString("Invalid username or password"));

        Response login = RestAssured.given().cookies(challenge.cookies()).redirects().follow(false)
                .contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(302)
                .header("Location", savedRequest).extract().response();
        Assertions.assertEquals(0, login.getDetailedCookie("quarkus-redirect-location").getMaxAge());
        RestAssured.given().cookies(login.cookies()).redirects().follow(false).urlEncodingEnabled(false).get(savedRequest)
                .then().statusCode(302).header("Location", Matchers.allOf(
                        Matchers.startsWith("http://localhost:5173/callback?"),
                        Matchers.containsString("code="), Matchers.containsString("state=native-form-navigation")));
    }

    @Test
    void formRejectsAForeignSavedReturnAddress() {
        RestAssured.given().cookie("quarkus-redirect-location", "https://untrusted.example/")
                .redirects().follow(false).contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(401)
                .header("Location", Matchers.nullValue());
    }

    @Test
    void formLoginReusesPasswordAuthenticationAndEstablishesHttpOnlySession() {
        RestAssured.given().redirects().follow(false).contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "resource-owner").formParam("j_password", "incorrect")
                .post("/j_security_check").then().statusCode(302)
                .header("Location", Matchers.endsWith("/auth/login?error=true"));
        Response response = BrowserAuthenticationTest.login();
        Assertions.assertTrue(response.getDetailedCookie(COOKIE).isHttpOnly());
        Assertions.assertEquals("Lax", response.getDetailedCookie(COOKIE).getSameSite());
        Assertions.assertEquals(900, response.getDetailedCookie(COOKIE).getMaxAge());
        RestAssured.given().cookie(COOKIE, response.cookie(COOKIE)).get("/auth/login").then().statusCode(200)
                .body(Matchers.containsString("<h1>Sign in</h1>"));
        RestAssured.given().redirects().follow(false).contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "unknown-user").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(302)
                .header("Location", Matchers.endsWith("/auth/login?error=true"));
        RestAssured.given().contentType("application/json")
                .body(Map.of("username", "resource-owner", "password", "resource-owner-password"))
                .post("/auth/login").then().statusCode(404);
    }

    @Test
    void cookiesAndBearerTokensCannotSubstituteForEachOther() {
        Response login = BrowserAuthenticationTest.login();
        String token = BrowserAuthenticationTest.token(login.cookies(), "message.read");
        RestAssured.given().get("/api/messages").then().statusCode(401);
        RestAssured.given().cookies(login.cookies()).get("/api/messages").then().statusCode(401);
        RestAssured.given().header("Authorization", "Bearer " + login.cookie(COOKIE))
                .get("/api/messages").then().statusCode(401);
        BrowserAuthenticationTest.authorizationRequest().cookie(COOKIE + ".oidc", login.cookie(COOKIE + ".oidc"))
                .redirects().follow(false).get("/oauth2/authorize").then().statusCode(302);
        BrowserAuthenticationTest.authorizationRequest().cookie(COOKIE, token).redirects().follow(false)
                .get("/oauth2/authorize").then().statusCode(302);
        BrowserAuthenticationTest.authorizationRequest().header("Authorization", "Bearer " + token).redirects().follow(false)
                .get("/oauth2/authorize").then().statusCode(302);
        RestAssured.given().header("Authorization", "Bearer " + token).get("/api/messages")
                .then().statusCode(200).body("subject", Matchers.equalTo("resource-owner"));
    }

    @Test
    void resourceServerRequiresTheGrantedScope() {
        String token = BrowserAuthenticationTest.token(BrowserAuthenticationTest.login().cookies(), "openid");
        RestAssured.given().header("Authorization", "Bearer " + token).get("/api/messages").then().statusCode(403);
    }

    @Test
    void tamperedCookieAndUnknownConsentStateAreRejected() {
        String cookie = BrowserAuthenticationTest.login().cookie(COOKIE);
        String tampered = cookie.substring(0, 10) + (cookie.charAt(10) == 'A' ? 'B' : 'A')
                + cookie.substring(11);
        BrowserAuthenticationTest.authorizationRequest().cookie(COOKIE, tampered).redirects().follow(false)
                .get("/oauth2/authorize").then().statusCode(302);
        RestAssured.given().cookies(BrowserAuthenticationTest.login().cookies()).redirects().follow(false)
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", "authorization-code-public-client").formParam("state", "not-an-authorization")
                .post("/oauth2/authorize").then().statusCode(400).header("Location", Matchers.nullValue());
    }

    @Test
    void corsAllowsBearerApiRequestsWithoutCookiesAndRejectsForeignLoginPosts() {
        RestAssured.given().header("Origin", "http://localhost:5173")
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "authorization").options("/api/messages")
                .then().statusCode(200).header("Access-Control-Allow-Origin", "http://localhost:5173")
                .header("Access-Control-Allow-Credentials", Matchers.not("true"));
        RestAssured.given().header("Origin", "https://untrusted.example").contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(403);
    }

    @Test
    void silentAuthorizationReturnsLoginRequiredThenIssuesATokenAcceptedByQuarkusOidc() {
        Response anonymous = BrowserAuthenticationTest.authorizationRequest().queryParam("prompt", "none")
                .get("/oauth2/authorize").then().statusCode(302)
                .header("Location", Matchers.allOf(Matchers.startsWith("http://localhost:5173/callback?"),
                        Matchers.containsString("error=login_required"), Matchers.containsString("state=silent-state")))
                .extract().response();
        Assertions.assertNull(anonymous.cookie("quarkus-redirect-location"));
        Response signedIn = BrowserAuthenticationTest.authorizationRequest()
                .cookies(BrowserAuthenticationTest.login().cookies())
                .queryParam("prompt", "none").get("/oauth2/authorize").then().statusCode(302)
                .header("Location", Matchers.containsString("state=silent-state")).extract().response();
        String code = Arrays.stream(URI.create(signedIn.header("Location")).getRawQuery().split("&"))
                .filter(value -> value.startsWith("code="))
                .map(value -> URLDecoder.decode(value.substring(5), StandardCharsets.UTF_8)).findFirst().orElseThrow();
        String token = RestAssured.given().auth().preemptive()
                .basic("authorization-code-confidential-client", "authorization-code-client-secret")
                .contentType("application/x-www-form-urlencoded").formParam("grant_type", "authorization_code")
                .formParam("redirect_uri", "http://localhost:5173/callback").formParam("code", code)
                .formParam("code_verifier", VERIFIER).post("/oauth2/token")
                .then().statusCode(200).body("token_type", Matchers.equalTo("Bearer")).extract().path("access_token");
        RestAssured.given().auth().oauth2(token).get("/api/messages")
                .then().statusCode(200).body("subject", Matchers.equalTo("resource-owner"));
    }

    @Test
    void pushedAuthorizationCompletesBrowserLoginAndIssuesAnOidcResourceToken() {
        String client = "authorization-code-confidential-client";
        String uri = RestAssured.given().auth().preemptive().basic(client, "authorization-code-client-secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", client).formParam("response_type", "code")
                .formParam("redirect_uri", "http://localhost:5173/callback").formParam("scope", "openid message.read")
                .formParam("state", "par-browser-state")
                .formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .formParam("code_challenge_method", "S256").post("/oauth2/par")
                .then().statusCode(201).extract().path("request_uri");
        var challenge = RestAssured.given().redirects().follow(false).queryParam("client_id", client)
                .queryParam("request_uri", uri)
                .get("/oauth2/authorize").then().statusCode(302).extract().response();
        String original = challenge.cookie("quarkus-redirect-location");
        Assertions.assertNotNull(original);
        var login = RestAssured.given().redirects().follow(false).cookies(challenge.cookies())
                .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(302).header("Location", original).extract().response();
        var authorization = RestAssured.given().redirects().follow(false).urlEncodingEnabled(false).cookies(login.cookies())
                .get(original).then().statusCode(302).header("Location", Matchers.containsString("state=par-browser-state"))
                .extract().response();
        String code = Arrays.stream(URI.create(authorization.header("Location")).getRawQuery().split("&"))
                .filter(value -> value.startsWith("code="))
                .map(value -> URLDecoder.decode(value.substring(5), StandardCharsets.UTF_8))
                .findFirst().orElseThrow();
        RestAssured.given().redirects().follow(false).cookies(login.cookies()).queryParam("client_id", client)
                .queryParam("request_uri", uri).get("/oauth2/authorize").then().statusCode(400)
                .header("Location", Matchers.nullValue());
        String token = RestAssured.given().auth().preemptive().basic(client, "authorization-code-client-secret")
                .contentType("application/x-www-form-urlencoded").formParam("grant_type", "authorization_code")
                .formParam("code", code).formParam("redirect_uri", "http://localhost:5173/callback")
                .formParam("code_verifier", VERIFIER)
                .post("/oauth2/token").then().statusCode(200).extract().path("access_token");
        RestAssured.given().auth().oauth2(token).get("/api/messages").then().statusCode(200)
                .body("subject", Matchers.equalTo("resource-owner"));
    }

    private static io.restassured.specification.RequestSpecification authorizationRequest() {
        return RestAssured.given().redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", "authorization-code-confidential-client")
                .queryParam("redirect_uri", "http://localhost:5173/callback").queryParam("scope", "openid message.read")
                .queryParam("state", "silent-state")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256");
    }

    private static Response login() {
        return RestAssured.given().redirects().follow(false).contentType("application/x-www-form-urlencoded")
                .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                .post("/j_security_check").then().statusCode(302)
                .header("Location", Matchers.endsWith("/auth/login")).extract().response();
    }

    private static String token(Map<String, String> cookies, String scope) {
        Response authorization = RestAssured.given().cookies(cookies).redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", "authorization-code-confidential-client")
                .queryParam("redirect_uri", "http://localhost:5173/callback").queryParam("scope", scope)
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256").get("/oauth2/authorize")
                .then().statusCode(302).extract().response();
        String code = Arrays.stream(URI.create(authorization.header("Location")).getRawQuery().split("&"))
                .filter(value -> value.startsWith("code="))
                .map(value -> URLDecoder.decode(value.substring(5), StandardCharsets.UTF_8)).findFirst().orElseThrow();
        return RestAssured.given().auth().preemptive()
                .basic("authorization-code-confidential-client", "authorization-code-client-secret")
                .contentType("application/x-www-form-urlencoded").formParam("grant_type", "authorization_code")
                .formParam("redirect_uri", "http://localhost:5173/callback").formParam("code", code)
                .formParam("code_verifier", VERIFIER).post("/oauth2/token")
                .then().statusCode(200).extract().path("access_token");
    }
}
