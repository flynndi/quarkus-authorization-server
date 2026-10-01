package io.quarkiverse.authorization.server.it.registration;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;

/** A real process restart, not a new repository object or re-seeded target client. */
class OidcClientRegistrationJdbcRestartIT {
    @TempDir
    Path directory;
    private final String tokenPrefix = UUID.randomUUID().toString();

    @Test
    void restoresDynamicallyRegisteredClientTokensAndPendingCodeWithoutResurrectingBootstrap() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        Process process = start(port, "first");
        try {
            var http = new ClientRegistrationRequests(port);
            var registration = http.register(this.tokenPrefix + "-restart", false);
            http.read(registration);
            http.verifyJwt(registration.path("registration_access_token"));
            String code = http.authorize(registration, "restart-registration-nonce");
            stop(process);

            // Inspect committed rows while the process is stopped, without using extension repository objects.
            try (var connection = DriverManager.getConnection(jdbcUrl(), "sa", "sa")) {
                try (var statement = connection
                        .prepareStatement("select client_secret from oauth2_registered_client where client_id = ?")) {
                    statement.setString(1, registration.path("client_id"));
                    try (var rows = statement.executeQuery()) {
                        assertTrue(rows.next());
                        String stored = rows.getString(1);
                        assertNotEquals(registration.path("client_secret"), stored);
                        assertTrue(stored.startsWith("$2"));
                    }
                }
                try (var statement = connection.createStatement();
                        var rows = statement.executeQuery(
                                "select access_token_metadata, refresh_token_metadata from oauth2_authorization where id = 'initial-restart'")) {
                    assertTrue(rows.next());
                    for (int column = 1; column <= 2; column++) {
                        var metadata = new JsonPath(new String(rows.getBytes(column), StandardCharsets.UTF_8));
                        assertEquals("token-metadata", metadata.getString("kind"));
                        assertEquals(Boolean.TRUE, metadata.getBoolean("data.invalidated"));
                    }
                }
            }

            process = start(port, "second");
            http = new ClientRegistrationRequests(port);
            http.read(registration);
            http.post(this.tokenPrefix + "-restart",
                    java.util.Map.of("redirect_uris", List.of(ClientRegistrationRequests.REDIRECT)))
                    .then().statusCode(401).body("error", equalTo("invalid_token"));
            // Both the newly registered client/hash and the unused code must survive the restart.
            var tokens = http.exchange(registration, code).then().statusCode(200).extract().response();
            var id = http.verifyJwt(tokens.path("id_token"));
            assertEquals("restart-registration-nonce", id.get("nonce"));
            assertEquals(List.of(registration.<String> path("client_id")), id.get("aud"));
            http.request().header("Authorization", "Bearer " + tokens.<String> path("access_token"))
                    .get(http.endpoint("userinfo_endpoint")).then().statusCode(200).body("sub", equalTo("resource-owner"));
            http.clientRequest(registration).contentType(ContentType.URLENC).formParam("grant_type", "refresh_token")
                    .formParam("refresh_token", tokens.<String> path("refresh_token")).post(http.endpoint("token_endpoint"))
                    .then().statusCode(200);
            http.exchange(registration, code).then().statusCode(400).body("error", equalTo("invalid_grant"));
        } finally {
            stop(process);
        }
    }

    private String jdbcUrl() {
        return "jdbc:h2:file:" + this.directory.resolve("registration") + ";DB_CLOSE_ON_EXIT=FALSE";
    }

    private Process start(int port, String run) throws Exception {
        Path build = Path.of("build").toAbsolutePath();
        Properties artifact = new Properties();
        try (var input = Files.newInputStream(build.resolve("quarkus-artifact.properties"))) {
            artifact.load(input);
        }
        List<String> command = new ArrayList<>();
        boolean nativeImage = "native".equals(artifact.getProperty("type"));
        Path application = build.resolve(artifact.getProperty("path"));
        command.add(nativeImage ? application.toString() : Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-Dquarkus.http.port=" + port);
        command.add("-Dquarkus.authorization-server.issuer=http://localhost:" + port);
        command.add("-Dquarkus.datasource.jdbc.url=" + jdbcUrl());
        command.add("-Dregistration-test.token-prefix=" + this.tokenPrefix);
        if (!nativeImage) {
            command.add("-jar");
            command.add(application.toString());
        }
        Path log = this.directory.resolve(run + ".log");
        Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        long deadline = System.nanoTime() + Duration.ofSeconds(40).toNanos();
        while (process.isAlive() && System.nanoTime() < deadline) {
            try {
                if (given().baseUri("http://localhost").port(port).basePath("")
                        .get("/.well-known/openid-configuration").statusCode() == 200) {
                    return process;
                }
            } catch (Exception ignored) {
                // Do not substitute direct JWKS or an in-process readiness signal for real discovery.
            }
            Thread.sleep(100);
        }
        stop(process);
        fail("Registration application did not start: " + Files.readString(log));
        return process;
    }

    private static void stop(Process process) throws InterruptedException {
        if (process != null && process.isAlive()) {
            process.destroy();
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly().waitFor(10, TimeUnit.SECONDS);
            }
        }
    }
}
