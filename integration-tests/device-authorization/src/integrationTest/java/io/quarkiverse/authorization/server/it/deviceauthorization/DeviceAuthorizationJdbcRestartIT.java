package io.quarkiverse.authorization.server.it.deviceauthorization;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** Restarts the packaged JVM or native process over one H2 file without mutating authorization state from the test. */
class DeviceAuthorizationJdbcRestartIT {

    private static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(5);

    @TempDir
    Path directory;

    @Test
    void restoresPendingApprovedAndExpiredDeviceSessionsAcrossProcessRestart() throws Exception {
        int port = availablePort();
        Process process = start(port, "first");
        try {
            Response pendingPublic = startPublicDevice(port);
            Response approvedConfidential = startConfidentialDevice(port,
                    DeviceAuthorizationServerConfig.CONFIDENTIAL_CLIENT,
                    DeviceAuthorizationServerConfig.CONFIDENTIAL_SECRET);
            authorizeInBrowser(port, approvedConfidential, true).then().statusCode(200)
                    .body(containsString("Device authorized"));
            Response expiresWhileStopped = startConfidentialDevice(port,
                    DeviceAuthorizationServerConfig.SHORT_LIVED_CLIENT,
                    DeviceAuthorizationServerConfig.SHORT_LIVED_SECRET);

            stop(process);
            process = null;
            assertTrue(Files.exists(this.directory.resolve("device-authorizations.mv.db")));
            TimeUnit.SECONDS.sleep(4);
            process = start(port, "second");

            String pendingDeviceCode = pendingPublic.path("device_code");
            long previousPoll = System.nanoTime();
            pollPublic(port, pendingDeviceCode).then().statusCode(400)
                    .body("error", equalTo("authorization_pending"));
            // A new browser session is used after restart; JDBC recovery is not session replication.
            authorizeInBrowser(port, pendingPublic, true).then().statusCode(200)
                    .body(containsString("Device authorized"));
            awaitNextPoll(previousPoll);
            Response publicTokens = pollPublic(port, pendingDeviceCode).then().statusCode(200)
                    .body("access_token", notNullValue())
                    .body("refresh_token", org.hamcrest.Matchers.nullValue())
                    .extract().response();
            String publicAccessToken = publicTokens.path("access_token");
            assertEquals(3, publicAccessToken.split("\\.").length);
            resource(port, publicAccessToken).then().statusCode(200)
                    .body("subject", equalTo(DeviceAuthorizationServerConfig.RESOURCE_OWNER))
                    .body("format", equalTo("self-contained"));

            String approvedDeviceCode = approvedConfidential.path("device_code");
            Response confidentialTokens = pollConfidential(port,
                    DeviceAuthorizationServerConfig.CONFIDENTIAL_CLIENT,
                    DeviceAuthorizationServerConfig.CONFIDENTIAL_SECRET,
                    approvedDeviceCode).then().statusCode(200)
                    .body("access_token", notNullValue())
                    .body("refresh_token", notNullValue())
                    .extract().response();
            String confidentialAccessToken = confidentialTokens.path("access_token");
            assertFalse(confidentialAccessToken.contains("."));
            resource(port, confidentialAccessToken).then().statusCode(200)
                    .body("subject", equalTo(DeviceAuthorizationServerConfig.RESOURCE_OWNER))
                    .body("format", equalTo("reference"))
                    .body("introspection_active", equalTo(true))
                    .body("introspection_client_id",
                            equalTo(DeviceAuthorizationServerConfig.CONFIDENTIAL_CLIENT));

            pollPublic(port, pendingDeviceCode).then().statusCode(400)
                    .body("error", equalTo("access_denied"));
            pollConfidential(port, DeviceAuthorizationServerConfig.CONFIDENTIAL_CLIENT,
                    DeviceAuthorizationServerConfig.CONFIDENTIAL_SECRET, approvedDeviceCode)
                    .then().statusCode(400).body("error", equalTo("access_denied"));
            pollConfidential(port, DeviceAuthorizationServerConfig.SHORT_LIVED_CLIENT,
                    DeviceAuthorizationServerConfig.SHORT_LIVED_SECRET,
                    expiresWhileStopped.<String> path("device_code"))
                    .then().statusCode(400).body("error", equalTo("expired_token"));
        } finally {
            stop(process);
        }
    }

    private Response startPublicDevice(int port) {
        return request(port).contentType(ContentType.URLENC)
                .formParam("client_id", DeviceAuthorizationServerConfig.PUBLIC_CLIENT)
                .formParam("scope", "message.read")
                .post("/oauth2/device_authorization")
                .then().statusCode(200).extract().response();
    }

    private Response startConfidentialDevice(int port, String clientId, String secret) {
        return request(port).auth().preemptive().basic(clientId, secret)
                .contentType(ContentType.URLENC)
                .formParam("scope", "message.read")
                .post("/oauth2/device_authorization")
                .then().statusCode(200).extract().response();
    }

    private Response pollPublic(int port, String deviceCode) {
        return request(port).contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", deviceCode)
                .formParam("client_id", DeviceAuthorizationServerConfig.PUBLIC_CLIENT)
                .post("/oauth2/token");
    }

    private Response pollConfidential(int port, String clientId, String secret, String deviceCode) {
        return request(port).auth().preemptive().basic(clientId, secret)
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                .formParam("device_code", deviceCode)
                .post("/oauth2/token");
    }

    private Response authorizeInBrowser(int port, Response deviceAuthorization, boolean approve) {
        String verificationUriComplete = deviceAuthorization.path("verification_uri_complete");
        Response challenge = request(port).get(pathAndQuery(verificationUriComplete));
        challenge.then().statusCode(302).header("Location", containsString("/login"));

        Map<String, String> cookies = new LinkedHashMap<>(challenge.cookies());
        request(port).cookies(cookies).get(pathAndQuery(challenge.header("Location")))
                .then().statusCode(200).body(containsString("/j_security_check"));
        Response login = request(port).cookies(cookies).contentType(ContentType.URLENC)
                .formParam("j_username", DeviceAuthorizationServerConfig.RESOURCE_OWNER)
                .formParam("j_password", DeviceAuthorizationServerConfig.RESOURCE_OWNER_PASSWORD)
                .post("/j_security_check");
        login.then().statusCode(302);
        cookies.putAll(login.cookies());

        Response consent = request(port).cookies(cookies).get(pathAndQuery(login.header("Location")));
        consent.then().statusCode(200).body(containsString("Confirm your device"));
        cookies.putAll(consent.cookies());
        RequestSpecification submission = request(port).cookies(cookies).contentType(ContentType.URLENC)
                .formParam("client_id", hidden(consent, "client_id"))
                .formParam("user_code", hidden(consent, "user_code"))
                .formParam("state", hidden(consent, "state"))
                .formParam("approved", approve);
        if (approve) {
            submission.formParam("scope", "message.read");
        }
        return submission.post("/oauth2/device_verification");
    }

    private Process start(int port, String run) throws Exception {
        Path build = Path.of("build").toAbsolutePath();
        Properties artifact = new Properties();
        try (var input = Files.newInputStream(build.resolve("quarkus-artifact.properties"))) {
            artifact.load(input);
        }
        Path application = build.resolve(artifact.getProperty("path"));
        boolean nativeImage = "native".equals(artifact.getProperty("type"));
        List<String> command = new ArrayList<>();
        command.add(nativeImage ? application.toString()
                : Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-Dquarkus.http.port=" + port);
        command.add("-Dquarkus.authorization-server.issuer=http://localhost:" + port);
        command.add("-Dquarkus.datasource.jdbc.url=jdbc:h2:file:" + this.directory.resolve("device-authorizations")
                + ";DB_CLOSE_ON_EXIT=FALSE");
        command.add("-Dquarkus.log.level=INFO");
        if (!nativeImage) {
            command.add("-jar");
            command.add(application.toString());
        }
        Path log = this.directory.resolve(run + ".log");
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(log.toFile())
                .start();
        long deadline = System.nanoTime() + Duration.ofSeconds(40).toNanos();
        while (process.isAlive() && System.nanoTime() < deadline) {
            try {
                if (request(port).get("/.well-known/oauth-authorization-server").statusCode() == 200) {
                    return process;
                }
            } catch (Exception ignored) {
                // The packaged application is ready only after its real HTTP endpoint responds.
            }
            Thread.sleep(100);
        }
        stop(process);
        fail("Application did not start: " + Files.readString(log));
        return process;
    }

    private static int availablePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static void stop(Process process) throws InterruptedException {
        if (process != null && process.isAlive()) {
            process.destroy();
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly().waitFor(10, TimeUnit.SECONDS);
            }
        }
    }

    private static RequestSpecification request(int port) {
        return RestAssured.given().baseUri("http://localhost").basePath("").port(port)
                .redirects().follow(false);
    }

    private static Response resource(int port, String accessToken) {
        return request(port).header("Authorization", "Bearer " + accessToken).get("/api/messages");
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
        return uri.getRawQuery() == null ? uri.getRawPath() : uri.getRawPath() + "?" + uri.getRawQuery();
    }

    private static void awaitNextPoll(long previousPoll) throws InterruptedException {
        long remaining = DEFAULT_POLL_INTERVAL.toNanos() - (System.nanoTime() - previousPoll);
        if (remaining > 0) {
            TimeUnit.NANOSECONDS.sleep(remaining);
        }
    }
}
