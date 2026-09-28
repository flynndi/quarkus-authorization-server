package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.OAuth2DeviceVerificationPage;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceConsentService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceVerificationService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.DefaultDeviceVerificationPage;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceVerificationEndpointHandler;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

class OAuth2DeviceVerificationEndpointTest {

    private static final String DEVICE_AUTHORIZATION_PATH = "/device/authorize";
    private static final String DEVICE_VERIFICATION_PATH = "/device/activate";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(
                            LogoutTestApplication.class,
                            LogoutTestApplication.PasswordProvider.class)
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.http.root-path=/api
                                                    quarkus.http.auth.proactive=false
                                                    quarkus.http.auth.form.enabled=true
                                                    quarkus.http.auth.form.login-page=/api/login
                                                    quarkus.http.auth.form.landing-page=
                                                    quarkus.http.auth.form.error-page=
                                                    quarkus.http.auth.session.encryption-key=device-verification-browser-test-key
                                                    quarkus.authorization-server.issuer=http://localhost:8081/api
                                                    quarkus.authorization-server.device-authorization-endpoint=/device/authorize
                                                    quarkus.authorization-server.device-verification-endpoint=/device/activate
                                                    quarkus.authorization-server.clients.device-client.client-secret=%s
                                                    quarkus.authorization-server.clients.device-client.authorization-grant-types=urn:ietf:params:oauth:grant-type:device_code
                                                    quarkus.authorization-server.clients.device-client.scopes=message.read,message.write
                                                    """
                                                    .formatted(
                                                            io.quarkus.elytron.security.common.BcryptUtil
                                                                    .bcryptHash(
                                                                            "device-secret"))),
                                    "application.properties"));

    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    Instance<DeviceVerificationService> verificationProvider;
    @Inject
    Instance<DeviceConsentService> consentProvider;
    @Inject
    Instance<OAuth2DeviceVerificationEndpointHandler> endpointHandler;
    @Inject
    OAuth2DeviceVerificationPage verificationPage;

    @Test
    void restoresLoginDisplaysConsentAndApprovesDevice() {
        IssuedDevice issued = issue("message.read message.write");

        Response challenge = given().redirects().follow(false)
                .queryParam("user_code", issued.userCode())
                .get(DEVICE_VERIFICATION_PATH);
        challenge.then().statusCode(302).header("Location", containsString("/login"));
        OAuth2Authorization pending = authorization(issued.userCode());
        assertEquals("device-client", pending.getPrincipalName());
        assertNull(pending.getAttribute(SecurityIdentity.class.getName()));
        assertNull(pending.getAttribute(OAuth2ParameterNames.STATE));

        BrowserSession browser = login(challenge);
        Response consentPage = given().cookies(browser.cookies()).redirects().follow(false)
                .get(browser.location());
        consentPage
                .then()
                .statusCode(200)
                .contentType(ContentType.HTML)
                .body(containsString("Confirm your device"))
                .body(containsString("message.read"))
                .body(containsString("message.write"));
        browser.cookies().putAll(consentPage.cookies());

        String state = hidden(consentPage.asString(), "state");
        assertNull(consentPage.cookie("q_auth_device_csrf"));
        assertTrue(authorization(issued.userCode()).getToken(OAuth2UserCode.class).isActive());
        assertTrue(consentPage.asString().contains("id=\"device-user-code\">" + issued.userCode()));
        given().cookies(browser.cookies())
                .contentType(ContentType.URLENC)
                .formParam("client_id", "device-client")
                .formParam("user_code", issued.userCode())
                .formParam("state", state)
                .formParam("scope", "message.read", "message.write")
                .formParam("approved", true)
                .post(DEVICE_VERIFICATION_PATH)
                .then()
                .statusCode(200)
                .contentType(ContentType.HTML)
                .body(containsString("Device authorized"));

        OAuth2Authorization approved = authorization(issued.userCode());
        assertEquals("resource-owner", approved.getPrincipalName());
        assertEquals(Set.of("message.read", "message.write"), approved.getAuthorizedScopes());
        SecurityIdentity snapshot = assertInstanceOf(
                QuarkusSecurityIdentity.class,
                approved.getAttribute(SecurityIdentity.class.getName()));
        assertEquals("resource-owner", snapshot.getPrincipal().getName());
        assertFalse(approved.getToken(OAuth2UserCode.class).isActive());
        assertTrue(approved.getToken(OAuth2DeviceCode.class).isActive());
        assertNull(approved.getAttribute(OAuth2ParameterNames.STATE));
        assertNull(approved.getAttribute(OAuth2ParameterNames.SCOPE));

        given().cookies(browser.cookies()).queryParam("user_code", issued.userCode())
                .get(DEVICE_VERIFICATION_PATH)
                .then().statusCode(400).contentType(ContentType.HTML)
                .body(containsString("invalid_grant"))
                .body(containsString("already been used"));
    }

    @Test
    void entryFormAcceptsUserCodeAndDenialInvalidatesBothCodes() {
        IssuedDevice issued = issue("message.read");
        BrowserSession browser = login(null);

        Response entry = given().cookies(browser.cookies()).get(DEVICE_VERIFICATION_PATH);
        entry.then().statusCode(200).contentType(ContentType.HTML)
                .body(containsString("name=\"user_code\""));
        assertNull(entry.cookie("q_auth_device_csrf"));
        assertFalse(entry.asString().contains("csrf_token"));

        Response consent = given().cookies(browser.cookies())
                .contentType(ContentType.URLENC)
                .formParam("user_code", issued.userCode())
                .post(DEVICE_VERIFICATION_PATH);
        consent.then().statusCode(200).body(containsString("Confirm your device"));
        assertNull(consent.cookie("q_auth_device_csrf"));
        assertTrue(authorization(issued.userCode()).getToken(OAuth2UserCode.class).isActive());

        given().cookies(browser.cookies())
                .contentType(ContentType.URLENC)
                .formParam("client_id", "device-client")
                .formParam("user_code", issued.userCode())
                .formParam("state", hidden(consent.asString(), "state"))
                .formParam("approved", false)
                .post(DEVICE_VERIFICATION_PATH)
                .then()
                .statusCode(400)
                .contentType(ContentType.HTML)
                .body(containsString("access_denied"))
                .body(containsString("Device authorization was denied"));

        OAuth2Authorization denied = authorization(issued.userCode());
        assertFalse(denied.getToken(OAuth2UserCode.class).isActive());
        assertFalse(denied.getToken(OAuth2DeviceCode.class).isActive());
        assertNull(denied.getAttribute(OAuth2ParameterNames.STATE));
    }

    @Test
    void rejectsMissingOrForgedConfirmationParametersWithoutChangingPendingState() {
        IssuedDevice issued = issue("message.read");
        BrowserSession browser = login(null);
        Response page = confirmation(browser, issued);
        String state = hidden(page.asString(), "state");

        for (Map<String, String> fields : java.util.List.of(
                Map.of("approved", "true"),
                Map.of("state", "forged-state", "approved", "true"),
                Map.of("state", state),
                Map.of("state", state, "approved", "yes"))) {
            given().cookies(browser.cookies())
                    .contentType(ContentType.URLENC)
                    .formParam("client_id", "device-client")
                    .formParam("user_code", issued.userCode())
                    .formParams(fields)
                    .post(DEVICE_VERIFICATION_PATH)
                    .then()
                    .statusCode(400)
                    .body(containsString("invalid_request"));
            OAuth2Authorization pending = authorization(issued.userCode());
            assertEquals(state, pending.getAttribute(OAuth2ParameterNames.STATE));
            assertTrue(pending.getToken(OAuth2UserCode.class).isActive());
            assertTrue(pending.getToken(OAuth2DeviceCode.class).isActive());
        }
    }

    @Test
    void independentDeviceTabsCanBeConfirmedWithoutOverwritingBrowserTokens() {
        BrowserSession browser = login(null);
        IssuedDevice first = issue("message.read");
        IssuedDevice second = issue("message.read");
        Response firstPage = confirmation(browser, first);
        Response secondPage = confirmation(browser, second);
        assertNotEquals(
                hidden(firstPage.asString(), "state"), hidden(secondPage.asString(), "state"));
        assertNull(firstPage.cookie("q_auth_device_csrf"));
        assertNull(secondPage.cookie("q_auth_device_csrf"));

        submit(browser, first, firstPage, true)
                .then()
                .statusCode(200)
                .body(containsString("Device authorized"));
        submit(browser, second, secondPage, false)
                .then()
                .statusCode(400)
                .body(containsString("access_denied"));
        assertFalse(authorization(first.userCode()).getToken(OAuth2UserCode.class).isActive());
        assertTrue(authorization(first.userCode()).getToken(OAuth2DeviceCode.class).isActive());
        assertFalse(authorization(second.userCode()).getToken(OAuth2DeviceCode.class).isActive());
    }

    private static Response confirmation(BrowserSession browser, IssuedDevice device) {
        return given().cookies(browser.cookies())
                .queryParam("user_code", device.userCode())
                .get(DEVICE_VERIFICATION_PATH)
                .then()
                .statusCode(200)
                .body(containsString("Confirm your device"))
                .extract()
                .response();
    }

    private static Response submit(
            BrowserSession browser, IssuedDevice device, Response page, boolean approved) {
        var submission = given().cookies(browser.cookies())
                .contentType(ContentType.URLENC)
                .formParam("client_id", "device-client")
                .formParam("user_code", device.userCode())
                .formParam("state", hidden(page.asString(), "state"))
                .formParam("approved", approved);
        if (approved) {
            submission.formParam("scope", "message.read");
        }
        return submission.post(DEVICE_VERIFICATION_PATH);
    }

    @Test
    void returnsExplicitUnknownCodeAndInstallsOnlyConfiguredMethods() {
        BrowserSession browser = login(null);
        given().cookies(browser.cookies()).queryParam("user_code", "ZZZZ-ZZZZ")
                .get(DEVICE_VERIFICATION_PATH)
                .then().statusCode(400).contentType(ContentType.HTML)
                .body(containsString("invalid_grant"));

        IssuedDevice issued = issue("message.read");
        OAuth2Authorization authorization = authorization(issued.userCode());
        Instant issuedAt = Instant.now().minusSeconds(600);
        this.authorizations.save(OAuth2Authorization.from(authorization)
                .token(new OAuth2UserCode(issued.userCode(), issuedAt, issuedAt.plusSeconds(300)))
                .build());
        given().cookies(browser.cookies()).queryParam("user_code", issued.userCode())
                .get(DEVICE_VERIFICATION_PATH)
                .then().statusCode(400).contentType(ContentType.HTML)
                .body(containsString("invalid_grant"))
                .body(containsString("expired"));

        given().cookies(browser.cookies()).contentType(ContentType.JSON).body("{}")
                .post(DEVICE_VERIFICATION_PATH).then().statusCode(415);
        given().cookies(browser.cookies()).put(DEVICE_VERIFICATION_PATH).then().statusCode(403);
        given().cookies(browser.cookies())
                .get("/oauth2/device_verification")
                .then()
                .statusCode(404);

        assertTrue(this.verificationProvider.isResolvable());
        assertTrue(this.consentProvider.isResolvable());
        assertTrue(this.endpointHandler.isResolvable());
        assertInstanceOf(DefaultDeviceVerificationPage.class, this.verificationPage);
    }

    private IssuedDevice issue(String scope) {
        Response response = given().auth().preemptive().basic("device-client", "device-secret")
                .contentType(ContentType.URLENC).formParam("scope", scope)
                .post(DEVICE_AUTHORIZATION_PATH)
                .then().statusCode(200).extract().response();
        return new IssuedDevice(response.path("user_code"));
    }

    private OAuth2Authorization authorization(String userCode) {
        OAuth2Authorization authorization = this.authorizations.findByToken(
                userCode, new OAuth2TokenType(OAuth2ParameterNames.USER_CODE));
        assertNotNull(authorization);
        return authorization;
    }

    private static BrowserSession login(Response challenge) {
        Map<String, String> cookies = new LinkedHashMap<>();
        if (challenge != null) {
            cookies.putAll(challenge.cookies());
        }
        Response login = given().cookies(cookies).redirects().follow(false)
                .contentType(ContentType.URLENC)
                .formParam("j_username", "resource-owner")
                .formParam("j_password", "password")
                .post("/j_security_check");
        if (challenge != null) {
            login.then().statusCode(302);
        } else {
            assertTrue(login.statusCode() == 200 || login.statusCode() == 302);
        }
        cookies.putAll(login.cookies());
        String location = challenge != null ? login.header("Location") : DEVICE_VERIFICATION_PATH;
        return new BrowserSession(cookies, location);
    }

    private static String hidden(String page, String name) {
        Matcher matcher = Pattern.compile("name=\\\"" + Pattern.quote(name) + "\\\" value=\\\"([^\\\"]+)\\\"")
                .matcher(page);
        assertTrue(matcher.find(), "hidden " + name);
        return matcher.group(1);
    }

    private record IssuedDevice(String userCode) {
    }

    private record BrowserSession(Map<String, String> cookies, String location) {
    }
}
