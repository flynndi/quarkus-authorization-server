package io.quarkiverse.authorization.server.it.tokenlifecycle;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** Verifies persisted active and revoked reference tokens across two real packaged JVM or native processes. */
class TokenLifecycleJdbcRestartIT {

    @TempDir
    Path directory;

    @Test
    void preservesActiveAndRevokedReferenceTokenStateAcrossProcessRestart() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        Process process = start(port, "first");
        try {
            String active = clientCredentials(port);
            String revoked = clientCredentials(port);
            assertFalse(active.contains("."));
            assertFalse(revoked.contains("."));
            resource(port, active).then().statusCode(200);
            resource(port, revoked).then().statusCode(200);
            revoke(port, revoked).then().statusCode(200);
            introspect(port, revoked).then().statusCode(200).body("active", equalTo(false));
            resource(port, revoked).then().statusCode(401);

            stop(process);
            process = start(port, "second");
            introspect(port, active).then().statusCode(200).body("active", equalTo(true));
            resource(port, active).then().statusCode(200);
            introspect(port, revoked).then().statusCode(200).body("active", equalTo(false));
            resource(port, revoked).then().statusCode(401);

            revoke(port, active).then().statusCode(200);
            introspect(port, active).then().statusCode(200).body("active", equalTo(false));
            resource(port, active).then().statusCode(401);
        } finally {
            stop(process);
        }
    }

    private String clientCredentials(int port) {
        return request(port).auth().preemptive().basic("opaque-machine", "opaque-secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials").formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200).extract().path("access_token");
    }

    private Response introspect(int port, String token) {
        return request(port).auth().preemptive().basic("resource-server", "resource-secret")
                .contentType("application/x-www-form-urlencoded").formParam("token", token)
                .post("/oauth2/introspect");
    }

    private Response revoke(int port, String token) {
        return request(port).auth().preemptive().basic("opaque-machine", "opaque-secret")
                .contentType("application/x-www-form-urlencoded").formParam("token", token)
                .post("/oauth2/revoke");
    }

    private Response resource(int port, String token) {
        return request(port).header("Authorization", "Bearer " + token).get("/lifecycle/messages");
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
        command.add("-Dquarkus.datasource.jdbc.url=jdbc:h2:file:" + this.directory.resolve("authorization")
                + ";DB_CLOSE_ON_EXIT=FALSE");
        command.add("-Dquarkus.log.level=INFO");
        if (!nativeImage) {
            command.add("-jar");
            command.add(application.toString());
        }
        Path log = this.directory.resolve(run + ".log");
        Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        long deadline = System.nanoTime() + Duration.ofSeconds(40).toNanos();
        while (process.isAlive() && System.nanoTime() < deadline) {
            try {
                if (request(port).get("/.well-known/openid-configuration").statusCode() == 200) {
                    return process;
                }
            } catch (Exception ignored) {
                // Readiness is the packaged process's real discovery endpoint.
            }
            Thread.sleep(100);
        }
        stop(process);
        fail("Token lifecycle application did not start: " + Files.readString(log));
        return process;
    }

    private static RequestSpecification request(int port) {
        return RestAssured.given().baseUri("http://localhost").basePath("").port(port).redirects().follow(false);
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
