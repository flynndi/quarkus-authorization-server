package io.quarkiverse.authorization.server.it.deviceauthorization;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** HTTP-only Device flow reused unchanged against the packaged JVM application. */
@QuarkusTest
public class DeviceAuthorizationTest {

    private static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(5);

    @Test
    void publicDeviceWaitsForBrowserApprovalThenUsesJwtAndCannotReplay() throws InterruptedException {
        given().get("/.well-known/oauth-authorization-server")
                .then()
                .statusCode(200)
                .body("device_authorization_endpoint", endsWith("/oauth2/device_authorization"))
                .body(
                        "grant_types_supported",
                        hasItem("urn:ietf:params:oauth:grant-type:device_code"));

        Response device = startPublicDevice();
        assertDeviceResponse(device);
        String deviceCode = device.path("device_code");

        long previousPoll = System.nanoTime();
        pollPublic(deviceCode).then().statusCode(400)
                .body("error", equalTo("authorization_pending"));

        authorizeInBrowser(device, true).then().statusCode(200)
                .contentType(ContentType.HTML)
                .body(containsString("Device authorized"));

        awaitNextPoll(previousPoll);
        Response tokens = pollPublic(deviceCode).then().statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", org.hamcrest.Matchers.nullValue())
                .body("scope", equalTo("message.read"))
                .body("$", not(hasKey("id_token")))
                .extract().response();
        String accessToken = tokens.path("access_token");
        assertEquals(3, accessToken.split("\\.").length);
        resource(accessToken).then().statusCode(200)
                .body("subject", equalTo(DeviceAuthorizationServerConfig.RESOURCE_OWNER))
                .body("format", equalTo("self-contained"));

        pollPublic(deviceCode).then().statusCode(400)
                .body("error", equalTo("access_denied"));
    }

    @Test
    void confidentialDeviceObservesPollingIntervalAndBrowserDenial() throws InterruptedException {
        Response device = startConfidentialDevice(
                DeviceAuthorizationServerConfig.CONFIDENTIAL_CLIENT,
                DeviceAuthorizationServerConfig.CONFIDENTIAL_SECRET);
        assertDeviceResponse(device);
        String deviceCode = device.path("device_code");

        long previousPoll = System.nanoTime();
        pollConfidential(DeviceAuthorizationServerConfig.CONFIDENTIAL_CLIENT,
                DeviceAuthorizationServerConfig.CONFIDENTIAL_SECRET, deviceCode)
                .then().statusCode(400).body("error", equalTo("authorization_pending"));

        authorizeInBrowser(device, false).then().statusCode(400)
                .contentType(ContentType.HTML)
                .body(containsString("access_denied"))
                .body(containsString("Device authorization was denied"));

        awaitNextPoll(previousPoll);
        pollConfidential(DeviceAuthorizationServerConfig.CONFIDENTIAL_CLIENT,
                DeviceAuthorizationServerConfig.CONFIDENTIAL_SECRET, deviceCode)
                .then().statusCode(400).body("error", equalTo("access_denied"));
    }

    @Test
    void historicalConsentStillRequiresConfirmationAndAllowsDeviceDenial() {
        Response first = startPublicDevice();
        authorizeInBrowser(first, true).then().statusCode(200);

        Response second = startPublicDevice();
        authorizeInBrowser(second, false)
                .then()
                .statusCode(400)
                .body(containsString("access_denied"));
        pollPublic(second.path("device_code"))
                .then()
                .statusCode(400)
                .body("error", equalTo("access_denied"));

        // A new device still needs confirmation, but declining another device kept its scope
        // consent.
        Response third = startPublicDevice();
        authorizeInBrowser(third, true).then().statusCode(200);
        pollPublic(third.path("device_code"))
                .then()
                .statusCode(200)
                .body("scope", equalTo("message.read"));
    }

    private static Response startPublicDevice() {
        return given().contentType(ContentType.URLENC)
                .formParam("client_id", DeviceAuthorizationServerConfig.PUBLIC_CLIENT)
                .formParam("scope", "message.read")
                .post("/oauth2/device_authorization");
    }

    private static Response startConfidentialDevice(String clientId, String secret) {
        return given().auth().preemptive().basic(clientId, secret)
                .contentType(ContentType.URLENC)
                .formParam("scope", "message.read")
                .post("/oauth2/device_authorization");
    }

    private static Response pollPublic(String deviceCode) {
        return given().contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", deviceCode)
                .formParam("client_id", DeviceAuthorizationServerConfig.PUBLIC_CLIENT)
                .post("/oauth2/token");
    }

    private static Response pollConfidential(String clientId, String secret, String deviceCode) {
        return given().auth().preemptive().basic(clientId, secret)
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", deviceCode)
                .post("/oauth2/token");
    }

    private static Response authorizeInBrowser(Response deviceAuthorization, boolean approve) {
        String verificationUriComplete = deviceAuthorization.path("verification_uri_complete");
        Response challenge = given().redirects().follow(false)
                .get(pathAndQuery(verificationUriComplete));
        challenge.then().statusCode(302).header("Location", containsString("/login"));

        Map<String, String> cookies = new LinkedHashMap<>(challenge.cookies());
        given().cookies(cookies).get(pathAndQuery(challenge.header("Location")))
                .then().statusCode(200).body(containsString("/j_security_check"));
        Response login = given().cookies(cookies).redirects().follow(false)
                .contentType(ContentType.URLENC)
                .formParam("j_username", DeviceAuthorizationServerConfig.RESOURCE_OWNER)
                .formParam("j_password", DeviceAuthorizationServerConfig.RESOURCE_OWNER_PASSWORD)
                .post("/j_security_check");
        login.then().statusCode(302);
        cookies.putAll(login.cookies());

        Response consent = given().cookies(cookies).redirects().follow(false)
                .get(pathAndQuery(login.header("Location")));
        consent.then()
                .statusCode(200)
                .contentType(ContentType.HTML)
                .body(containsString("Confirm your device"));
        assertFalse(consent.asString().contains("csrf_token"));
        assertNull(consent.cookie("q_auth_device_csrf"));
        assertTrue(
                consent.asString()
                        .contains(
                                "id=\"device-user-code\">"
                                        + deviceAuthorization.<String> path("user_code")));
        String clientId = hidden(consent, "client_id");
        String deviceCode = deviceAuthorization.path("device_code");
        Response pending = DeviceAuthorizationServerConfig.PUBLIC_CLIENT.equals(clientId)
                ? pollPublic(deviceCode)
                : pollConfidential(
                        DeviceAuthorizationServerConfig.CONFIDENTIAL_CLIENT,
                        DeviceAuthorizationServerConfig.CONFIDENTIAL_SECRET,
                        deviceCode);
        pending.then().statusCode(400).body("error", equalTo("authorization_pending"));
        cookies.putAll(consent.cookies());

        RequestSpecification submission = given().cookies(cookies)
                .contentType(ContentType.URLENC)
                .formParam("client_id", hidden(consent, "client_id"))
                .formParam("user_code", hidden(consent, "user_code"))
                .formParam("state", hidden(consent, "state"))
                .formParam("approved", approve);
        if (approve && consent.asString().contains("name=\"scope\"")) {
            submission.formParam("scope", "message.read");
        }
        return submission.post("/oauth2/device_verification");
    }

    private static void assertDeviceResponse(Response response) {
        response.then().statusCode(200)
                .body("device_code", notNullValue())
                .body("user_code", notNullValue())
                .body("verification_uri", endsWith("/oauth2/device_verification"))
                .body("verification_uri_complete", containsString("user_code="))
                .body("expires_in", greaterThan(0))
                .body("$", not(hasKey("interval")));
        assertNull(response.path("interval"));
    }

    private static Response resource(String accessToken) {
        return given().header("Authorization", "Bearer " + accessToken).get("/api/messages");
    }

    private static String hidden(Response page, String name) {
        Matcher matcher = Pattern.compile("name=\\\"" + Pattern.quote(name) + "\\\" value=\\\"([^\\\"]+)\\\"")
                .matcher(page.asString());
        assertTrue(matcher.find(), "Missing hidden field " + name);
        return matcher.group(1);
    }

    private static String pathAndQuery(String location) {
        assertNotNull(location);
        URI uri = URI.create(location);
        if (!uri.isAbsolute()) {
            return location;
        }
        return uri.getRawQuery() == null
                ? uri.getRawPath()
                : uri.getRawPath() + "?" + uri.getRawQuery();
    }

    private static void awaitNextPoll(long previousPoll) throws InterruptedException {
        long remaining = DEFAULT_POLL_INTERVAL.toNanos() - (System.nanoTime() - previousPoll);
        if (remaining > 0) {
            TimeUnit.NANOSECONDS.sleep(remaining);
        }
        assertFalse(System.nanoTime() - previousPoll < DEFAULT_POLL_INTERVAL.toNanos());
    }
}
