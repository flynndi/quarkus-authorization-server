package io.quarkiverse.authorization.server.it.dpop;

import static org.junit.jupiter.api.Assertions.fail;

import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.quarkiverse.authorization.server.it.common.dpop.client.DPoPClient;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** Restarts a real packaged process over the same file-backed H2 database, on JVM and native. */
class DPoPJdbcRestartIT {
    @TempDir
    Path directory;

    @Test
    void restoresCodeAndRotatedRefreshBindingsInASecondJvm() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        var client = new DPoPClient("http://localhost", port);
        var keys = new java.util.LinkedHashMap<String, org.jose4j.jwk.PublicJsonWebKey>();
        var pendingCodes = new java.util.LinkedHashMap<String, String>();
        var refreshTokens = new java.util.LinkedHashMap<String, String>();
        Process process = start(port, "first");
        try {
            for (String id : List.of("public-jwt", "public-opaque")) {
                var key = DPoPClient.key();
                keys.put(id, key);
                pendingCodes.put(id, client.code(id, key));
                Response tokens = client.exchange(id, client.code(id, key), client.proof(key));
                client.assertBound(tokens, key, "resource-owner");
                Response rotated = client.refresh(id, tokens.path("refresh_token"), client.proof(key));
                client.assertBound(rotated, key, "resource-owner");
                refreshTokens.put(id, rotated.path("refresh_token"));
            }
            stop(process);
            process = start(port, "second");
            for (String id : keys.keySet()) {
                var key = keys.get(id);
                var wrong = DPoPClient.key();
                client.exchange(id, pendingCodes.get(id), client.proof(wrong))
                        .then()
                        .statusCode(400)
                        .body("error", org.hamcrest.Matchers.equalTo("invalid_dpop_proof"));
                client.assertBound(
                        client.exchange(id, pendingCodes.get(id), client.proof(key)),
                        key,
                        "resource-owner");
                client.refresh(id, refreshTokens.get(id), null)
                        .then()
                        .statusCode(400)
                        .body("error", org.hamcrest.Matchers.equalTo("invalid_dpop_proof"));
                client.refresh(id, refreshTokens.get(id), client.proof(wrong))
                        .then()
                        .statusCode(400)
                        .body("error", org.hamcrest.Matchers.equalTo("invalid_dpop_proof"));
                client.assertBound(
                        client.refresh(id, refreshTokens.get(id), client.proof(key)),
                        key,
                        "resource-owner");
            }
        } finally {
            stop(process);
        }
    }

    @Test
    void restoresDeviceRefreshAndOtherGrantAccessBindingsInASecondJvm() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        var client = new DPoPClient("http://localhost", port);
        var keys = new java.util.LinkedHashMap<String, org.jose4j.jwk.PublicJsonWebKey>();
        var issued = new java.util.LinkedHashMap<String, Response>();
        var pendingDevices = new java.util.LinkedHashMap<String, String>();
        Process process = start(port, "grants-first");
        try {
            for (String id : List.of("device-jwt", "device-opaque")) {
                var key = DPoPClient.key();
                keys.put(id, key);
                Response pending = client.startDevice(id);
                client.approveDevice(pending, true);
                pendingDevices.put(id, pending.path("device_code"));
                Response device = client.startDevice(id);
                client.approveDevice(device, true);
                Response tokens = client.deviceExchange(id, device.path("device_code"))
                        .header("DPoP", client.proof(key))
                        .post("/oauth2/token");
                tokens.then().statusCode(200);
                Response rotated = client.refresh(id, tokens.path("refresh_token"), client.proof(key));
                client.assertBound(rotated, key, "resource-owner");
                issued.put(id, rotated);
            }
            String subject = client.exchange("public-jwt", client.code("public-jwt", null), null)
                    .then()
                    .statusCode(200)
                    .extract()
                    .path("access_token");
            for (String id : List.of("machine-jwt", "machine-opaque")) {
                for (boolean exchange : List.of(false, true)) {
                    String label = exchange ? id + "-exchange" : id;
                    var key = DPoPClient.key();
                    keys.put(label, key);
                    Response tokens = (exchange
                            ? client.tokenExchange(id, subject)
                            : client.clientCredentials(id))
                            .header("DPoP", client.proof(key))
                            .post("/oauth2/token");
                    tokens.then().statusCode(200);
                    issued.put(label, tokens);
                }
            }
            stop(process);
            process = start(port, "grants-second");
            for (var entry : issued.entrySet()) {
                String label = entry.getKey();
                client.assertBound(
                        entry.getValue(),
                        keys.get(label),
                        label.startsWith("device-") || label.endsWith("-exchange")
                                ? "resource-owner"
                                : label);
            }
            for (String id : pendingDevices.keySet()) {
                var key = keys.get(id);
                String refresh = issued.get(id).path("refresh_token");
                for (String proof : java.util.Arrays.asList(null, client.proof(DPoPClient.key()))) {
                    client.refresh(id, refresh, proof)
                            .then()
                            .statusCode(400)
                            .body("error", org.hamcrest.Matchers.equalTo("invalid_dpop_proof"));
                }
                client.assertBound(
                        client.refresh(id, refresh, client.proof(key)), key, "resource-owner");
                client.assertBound(
                        client.deviceExchange(id, pendingDevices.get(id))
                                .header("DPoP", client.proof(key))
                                .post("/oauth2/token"),
                        key,
                        "resource-owner");
            }
        } finally {
            stop(process);
        }
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
        if (nativeImage) {
            command.add(application.toString());
        } else {
            command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        }
        command.add("-Dquarkus.http.port=" + port);
        command.add("-Dquarkus.authorization-server.issuer=http://localhost:" + port);
        command.add(
                "-Dquarkus.datasource.jdbc.url=jdbc:h2:file:"
                        + this.directory.resolve("authorization")
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
                if (request(port).get("/.well-known/openid-configuration").statusCode() == 200) {
                    return process;
                }
            } catch (Exception ignored) {
                // A process is not ready until its real HTTP discovery endpoint responds.
            }
            Thread.sleep(100);
        }
        stop(process);
        fail("Application did not start: " + Files.readString(log));
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

    private static RequestSpecification request(int port) {
        return RestAssured.given()
                .baseUri("http://localhost")
                .basePath("")
                .port(port)
                .redirects()
                .follow(false);
    }
}
