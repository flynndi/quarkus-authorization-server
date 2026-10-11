package io.quarkiverse.authorization.server.it.oauth2;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.config.AuthorizationServerPersistence;
import io.quarkiverse.authorization.server.it.support.OAuthRequests;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

@QuarkusTest
public class BrowserAuthorizationTest {

    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    @Test
    void authorizationCodeCompletesLoginConsentTokenAndUserInfoAndRejectsReplay() {
        String code = BrowserAuthorizationTest.approveAuthorization();
        var tokens = BrowserAuthorizationTest.exchangeCode(code, VERIFIER).post("/oauth2/token")
                .then().statusCode(200).body("id_token", notNullValue()).body("refresh_token", notNullValue())
                .extract().response();
        String token = tokens.path("access_token");
        RestAssured.given().auth().oauth2(token).get("/api/resource/jsonWebToken")
                .then().statusCode(200).body("subject", equalTo("admin"));
        RestAssured.given().auth().oauth2(token).get("/userinfo")
                .then().statusCode(200).body("sub", equalTo("admin"));

        BrowserAuthorizationTest.exchangeCode(code, VERIFIER).post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("invalid_grant"));
    }

    @Test
    void rejectsAnIncorrectPkceVerifier() {
        String code = BrowserAuthorizationTest.approveAuthorization();
        BrowserAuthorizationTest.exchangeCode(code, "wrong-verifier-which-is-at-least-forty-three-characters-long")
                .post("/oauth2/token").then().statusCode(400).body("error", equalTo("invalid_grant"));
    }

    @Test
    void explicitConsentDenialReturnsTheOriginalState() {
        var cookies = OAuthRequests.login();
        String state = UUID.randomUUID().toString();
        // Other flows never approve profile, so this request always needs explicit consent.
        var page = BrowserAuthorizationTest.authorization(cookies, state, "openid profile").get("/oauth2/authorize")
                .then().statusCode(200).extract().response();
        String location = RestAssured.given().cookies(cookies).redirects().follow(false)
                .formParam("client_id", AuthorizationServerPersistence.CLIENT_ID)
                .formParam("state", OAuthRequests.hidden(page, "state"))
                .formParam("consent_action", "deny").post("/oauth2/authorize")
                .then().statusCode(302).extract().header("Location");

        assertEquals("access_denied", OAuthRequests.query(location, "error"));
        assertEquals(state, OAuthRequests.query(location, "state"));
    }

    @Test
    void unauthenticatedAuthorizationRedirectsToTheDefaultLoginPage() {
        BrowserAuthorizationTest.authorization(Map.of(), UUID.randomUUID().toString()).get("/oauth2/authorize")
                .then().statusCode(302).header("Location", containsString("/login"));
    }

    @Test
    void deviceAuthorizationRequiresApprovalAndConsumesTheDeviceCodeOnce() {
        var device = BrowserAuthorizationTest.newDevice();
        BrowserAuthorizationTest.pollDevice(device).post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("authorization_pending"));
        BrowserAuthorizationTest.confirmDevice(device, true);

        String token = BrowserAuthorizationTest.pollDevice(device).post("/oauth2/token")
                .then().statusCode(200).body("refresh_token", notNullValue()).extract().path("access_token");
        RestAssured.given().auth().oauth2(token).get("/api/resource/securityIdentity").then().statusCode(200);
        BrowserAuthorizationTest.pollDevice(device).post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("access_denied"));
    }

    @Test
    void deniedDeviceCannotObtainTokens() {
        var device = BrowserAuthorizationTest.newDevice();
        BrowserAuthorizationTest.confirmDevice(device, false);
        BrowserAuthorizationTest.pollDevice(device).post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("access_denied"));
    }

    private static RequestSpecification authorization(Map<String, String> cookies, String state) {
        return BrowserAuthorizationTest.authorization(cookies, state, "openid securityIdentity jsonWebToken");
    }

    private static RequestSpecification authorization(Map<String, String> cookies, String state, String scope) {
        return RestAssured.given().cookies(cookies).redirects().follow(false)
                .queryParam("response_type", "code").queryParam("client_id", AuthorizationServerPersistence.CLIENT_ID)
                .queryParam("redirect_uri", AuthorizationServerPersistence.POSTMAN_REDIRECT_URI)
                .queryParam("scope", scope).queryParam("state", state)
                .queryParam("code_challenge", CHALLENGE)
                .queryParam("code_challenge_method", "S256");
    }

    private static String approveAuthorization() {
        var cookies = OAuthRequests.login();
        String state = UUID.randomUUID().toString();
        var page = BrowserAuthorizationTest.authorization(cookies, state).get("/oauth2/authorize");
        String location;
        if (page.statusCode() == 200) {
            location = RestAssured.given().cookies(cookies).redirects().follow(false)
                    .formParam("client_id", AuthorizationServerPersistence.CLIENT_ID)
                    .formParam("state", OAuthRequests.hidden(page, "state"))
                    .formParam("scope", "securityIdentity", "jsonWebToken")
                    .formParam("consent_action", "approve").post("/oauth2/authorize")
                    .then().statusCode(302).extract().header("Location");
        } else {
            // Consent is persisted in JDBC and may already cover this user's requested scopes.
            location = page.then().statusCode(302).extract().header("Location");
        }
        assertEquals(state, OAuthRequests.query(location, "state"));
        return OAuthRequests.query(location, "code");
    }

    private static RequestSpecification exchangeCode(String code, String verifier) {
        return OAuthRequests.client().formParam("grant_type", "authorization_code").formParam("code", code)
                .formParam("redirect_uri", AuthorizationServerPersistence.POSTMAN_REDIRECT_URI)
                .formParam("code_verifier", verifier);
    }

    private static Response newDevice() {
        return OAuthRequests.client().formParam("scope", "securityIdentity")
                .post("/oauth2/device_authorization").then().statusCode(200)
                .body("user_code", notNullValue()).body("verification_uri", notNullValue())
                .extract().response();
    }

    private static RequestSpecification pollDevice(Response device) {
        return OAuthRequests.client().formParam("grant_type", DEVICE_GRANT)
                .formParam("device_code", device.<String> path("device_code"));
    }

    private static void confirmDevice(Response device, boolean approved) {
        var cookies = OAuthRequests.login();
        var page = RestAssured.given().cookies(cookies).queryParam("user_code", device.<String> path("user_code"))
                .get("/oauth2/device_verification").then().statusCode(200).extract().response();
        var submission = RestAssured.given().cookies(cookies).redirects().follow(false)
                .formParam("client_id", OAuthRequests.hidden(page, "client_id"))
                .formParam("user_code", OAuthRequests.hidden(page, "user_code"))
                .formParam("state", OAuthRequests.hidden(page, "state"))
                .formParam("approved", approved);
        if (approved) {
            submission.formParam("scope", "securityIdentity");
        }
        submission.post("/oauth2/device_verification").then().statusCode(approved ? 200 : 400);
    }
}
