package io.quarkiverse.authorization.server.deployment;

import java.util.Map;
import java.util.regex.Pattern;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

class DefaultLoginPageTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(LogoutTestApplication.class,
                    LogoutTestApplication.PasswordProvider.class, LogoutTestApplication.TrustedProvider.class)
                    .addAsResource(
                            new StringAsset(
                                    """
                                            quarkus.authorization-server.default-login-page-enabled=true
                                            quarkus.authorization-server.issuer=https://issuer.example.com
                                            quarkus.http.auth.form.enabled=true
                                            quarkus.http.auth.session.encryption-key=default-browser-login-test-key
                                            quarkus.authorization-server.clients.browser.client-authentication-methods=none
                                            quarkus.authorization-server.clients.browser.authorization-grant-types=authorization_code
                                            quarkus.authorization-server.clients.browser.redirect-uris=https://client.example.com/callback
                                            quarkus.authorization-server.clients.browser.scopes=message.read,message.write
                                            quarkus.authorization-server.clients.device.client-authentication-methods=none
                                            quarkus.authorization-server.clients.device.authorization-grant-types=urn:ietf:params:oauth:grant-type:device_code
                                            quarkus.authorization-server.clients.device.scopes=message.read
                                            """),
                            "application.properties"));

    @Test
    void quarkusFormRestoresOriginalRequestAndDefaultConsentIssuesCode() {
        Response challenge = DefaultLoginPageTest.authorizationRequest(Map.of(), "message.read");
        challenge.then().statusCode(302).header("Location", Matchers.endsWith("/login.html"));
        Map<String, String> navigation = challenge.cookies();
        String originalUrl = navigation.get("quarkus-redirect-location");
        Assertions.assertTrue(originalUrl.contains("state=client-state"));

        RestAssured.given().cookies(navigation).get("/login.html").then().statusCode(200)
                .header("Cache-Control", "no-store")
                .body(Matchers.containsString("action=\"/j_security_check\""))
                .body(Matchers.containsString("name=\"j_username\""))
                .body(Matchers.not(Matchers.containsString("<script")));
        Response failed = RestAssured.given().redirects().follow(false).cookies(navigation)
                .formParam("j_username", "code-user").formParam("j_password", "wrong")
                .post("/j_security_check");
        failed.then().statusCode(302).header("Location", Matchers.endsWith("/error.html"));
        RestAssured.get("/error.html").then().statusCode(200)
                .body(Matchers.containsString("Invalid username or password"));

        Response login = RestAssured.given().redirects().follow(false).cookies(navigation)
                .formParam("j_username", "code-user").formParam("j_password", "password")
                .post("/j_security_check");
        login.then().statusCode(302).header("Location", Matchers.equalTo(originalUrl));
        Assertions.assertTrue(login.getDetailedCookie("quarkus-credential").isHttpOnly());
        Assertions.assertEquals("Lax", login.getDetailedCookie("quarkus-credential").getSameSite());
        Response consent = RestAssured.given().cookies(login.cookies()).get(originalUrl);
        consent.then().statusCode(200).body(Matchers.containsString("code-user"))
                .body(Matchers.containsString("name=\"consent_action\" value=\"deny\""));
        DefaultLoginPageTest.submit(login.cookies(), DefaultLoginPageTest.state(consent), "approve", "message.read")
                .then().statusCode(302).header("Location", Matchers.containsString("?code="))
                .header("Location", Matchers.containsString("state=client-state"));
    }

    @Test
    void explicitDenialWithCheckedScopesPreservesEarlierConsentAndCannotBeReplayed() {
        Map<String, String> cookies = RestAssured.given().redirects().follow(false)
                .formParam("j_username", "deny-user").formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302).extract().cookies();
        Response first = DefaultLoginPageTest.authorizationRequest(cookies, "message.read");
        DefaultLoginPageTest.submit(cookies, DefaultLoginPageTest.state(first), "approve", "message.read")
                .then().statusCode(302).header("Location", Matchers.containsString("?code="));
        Response next = DefaultLoginPageTest.authorizationRequest(cookies, "message.read message.write");
        next.then().statusCode(200).body(Matchers.containsString("Previously authorized:"));
        String state = DefaultLoginPageTest.state(next);
        DefaultLoginPageTest.submit(cookies, state, "deny", "message.write")
                .then().statusCode(302).header("Location", Matchers.containsString("error=access_denied"))
                .header("Location", Matchers.not(Matchers.containsString("code=")));
        DefaultLoginPageTest.submit(cookies, state, "approve", "message.write")
                .then().statusCode(400).body("error", Matchers.equalTo("invalid_request"));
        DefaultLoginPageTest.authorizationRequest(cookies, "message.read")
                .then().statusCode(302).header("Location", Matchers.containsString("?code="));
    }

    @Test
    void deviceConfirmationRestoresTheRequestAfterDefaultLogin() {
        String userCode = RestAssured.given().formParam("client_id", "device").formParam("scope", "message.read")
                .post("/oauth2/device_authorization").then().statusCode(200).extract().path("user_code");
        Response challenge = RestAssured.given().redirects().follow(false).queryParam("user_code", userCode)
                .get("/oauth2/device_verification").then().statusCode(302)
                .header("Location", Matchers.endsWith("/login.html")).extract().response();
        String original = challenge.cookie("quarkus-redirect-location");
        Response login = RestAssured.given().redirects().follow(false).cookies(challenge.cookies())
                .formParam("j_username", "device-user").formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302).header("Location", original).extract().response();
        Response consent = RestAssured.given().cookies(login.cookies()).get(original)
                .then().statusCode(200).body(Matchers.containsString("Confirm your device")).extract().response();
        RestAssured.given().cookies(login.cookies()).formParam("client_id", "device")
                .formParam("user_code", userCode).formParam("state", DefaultLoginPageTest.state(consent))
                .formParam("scope", "message.read").formParam("approved", true).post("/oauth2/device_verification")
                .then().statusCode(200).body(Matchers.containsString("Device authorized"));
    }

    @Test
    void directLoginReturnsToAnExistingPageByDefault() {
        RestAssured.given().redirects().follow(false)
                .formParam("j_username", "direct-user").formParam("j_password", "password")
                .post("/j_security_check").then().statusCode(302)
                .header("Location", Matchers.endsWith("/login.html"));
    }

    @Test
    void onlyClaimsLoginAndErrorGetPages() {
        RestAssured.get("/unrelated").then().statusCode(404);
        RestAssured.given().post("/login.html").then().statusCode(404);
        RestAssured.get("/.well-known/oauth-authorization-server").then().statusCode(200);
    }

    private static Response authorizationRequest(Map<String, String> cookies, String scope) {
        return RestAssured.given().redirects().follow(false).cookies(cookies)
                .queryParam("response_type", "code").queryParam("client_id", "browser")
                .queryParam("scope", scope).queryParam("state", "client-state")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256").get("/oauth2/authorize");
    }

    private static String state(Response response) {
        var matcher = Pattern.compile("name=\"state\" value=\"([^\"]+)\"").matcher(response.asString());
        Assertions.assertTrue(matcher.find(), response.asString());
        return matcher.group(1);
    }

    private static Response submit(Map<String, String> cookies, String state, String action, String scope) {
        return RestAssured.given().redirects().follow(false).cookies(cookies).contentType(ContentType.URLENC)
                .formParam("client_id", "browser").formParam("state", state)
                .formParam("consent_action", action).formParam("scope", scope).post("/oauth2/authorize");
    }
}
