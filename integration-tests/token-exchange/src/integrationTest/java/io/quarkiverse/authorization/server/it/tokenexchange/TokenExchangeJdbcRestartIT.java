package io.quarkiverse.authorization.server.it.tokenexchange;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

/** Proves that a persisted composite subject can be exchanged after a real JVM or native process restart. */
class TokenExchangeJdbcRestartIT {

    @TempDir
    Path directory;

    @Test
    void restoresSubjectAndActorChainAcrossProcessRestart() throws Exception {
        int port = availablePort();
        Process process = start(port, "first");
        try {
            String subject = password(port, TokenExchangeServerConfig.DELEGATED_SUBJECT_CLIENT,
                    TokenExchangeServerConfig.DELEGATED_SUBJECT_SECRET);
            String actor = clientCredentials(port, TokenExchangeServerConfig.ACTOR_CLIENT,
                    TokenExchangeServerConfig.ACTOR_SECRET);
            String reference = password(port, TokenExchangeServerConfig.REFERENCE_SUBJECT_CLIENT,
                    TokenExchangeServerConfig.REFERENCE_SUBJECT_SECRET);
            String delegated = exchange(port, subject, actor).then().statusCode(200)
                    .extract().path("access_token");
            String secondActor = clientCredentials(port, TokenExchangeServerConfig.SECOND_ACTOR_CLIENT,
                    TokenExchangeServerConfig.SECOND_ACTOR_SECRET);
            resource(port, delegated).then().statusCode(200)
                    .body("subject", equalTo(TokenExchangeServerConfig.RESOURCE_OWNER))
                    .body("act.sub", equalTo(TokenExchangeServerConfig.ACTOR_CLIENT));

            stop(process);
            process = null;
            assertTrue(Files.exists(this.directory.resolve("token-exchange.mv.db")));
            process = start(port, "second");

            exchange(port, reference, TokenExchangeTest.JWT_TOKEN_TYPE, null).then().statusCode(400)
                    .body("error", equalTo("invalid_request"));
            exchange(port, reference, TokenExchangeTest.ACCESS_TOKEN_TYPE, null).then().statusCode(200);
            introspect(port, subject).then().statusCode(200).body("active", equalTo(true));
            introspect(port, actor).then().statusCode(200).body("active", equalTo(true));
            introspect(port, delegated).then().statusCode(200)
                    .body("active", equalTo(true))
                    .body("act.sub", equalTo(TokenExchangeServerConfig.ACTOR_CLIENT));
            String multiLevel = exchange(port, delegated, secondActor).then().statusCode(200)
                    .extract().path("access_token");
            assertEquals(3, multiLevel.split("\\.").length);
            resource(port, multiLevel).then().statusCode(200)
                    .body("subject", equalTo(TokenExchangeServerConfig.RESOURCE_OWNER))
                    .body("audience", hasItem("messages-api"))
                    .body("act.sub", equalTo(TokenExchangeServerConfig.SECOND_ACTOR_CLIENT))
                    .body("act.act.sub", equalTo(TokenExchangeServerConfig.ACTOR_CLIENT));
        } finally {
            stop(process);
        }
    }

    private static String password(int port, String clientId, String secret) {
        return request(port).auth().preemptive().basic(clientId, secret)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .formParam("username", TokenExchangeServerConfig.RESOURCE_OWNER)
                .formParam("password", TokenExchangeServerConfig.RESOURCE_OWNER_PASSWORD)
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200).extract().path("access_token");
    }

    private static String clientCredentials(int port, String clientId, String secret) {
        return request(port).auth().preemptive().basic(clientId, secret)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .post("/oauth2/token").then().statusCode(200).extract().path("access_token");
    }

    private static Response exchange(int port, String subject, String actor) {
        Response response = exchange(port, subject, TokenExchangeTest.JWT_TOKEN_TYPE, actor);
        response.then().body("issued_token_type", equalTo(TokenExchangeTest.JWT_TOKEN_TYPE));
        return response;
    }

    private static Response exchange(int port, String subject, String subjectType, String actor) {
        RequestSpecification request = request(port).auth().preemptive()
                .basic(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                        TokenExchangeServerConfig.JWT_EXCHANGE_SECRET)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", TokenExchangeTest.TOKEN_EXCHANGE_GRANT)
                .formParam("subject_token", subject)
                .formParam("subject_token_type", subjectType)
                .formParam("requested_token_type", TokenExchangeTest.JWT_TOKEN_TYPE)
                .formParam("audience", "messages-api")
                .formParam("scope", "message.read");
        if (actor != null) {
            request.formParam("actor_token", actor).formParam("actor_token_type", TokenExchangeTest.JWT_TOKEN_TYPE);
        }
        return request.post("/oauth2/token");
    }

    private Response introspect(int port, String token) {
        return request(port).auth().preemptive().basic("resource-server", "resource-secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token).post("/oauth2/introspect");
    }

    private static Response resource(int port, String token) {
        return request(port).header("Authorization", "Bearer " + token).get("/api/messages");
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
        command.add("-Dquarkus.datasource.jdbc.url=jdbc:h2:file:" + this.directory.resolve("token-exchange")
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
                // Readiness is the packaged process's real discovery endpoint.
            }
            Thread.sleep(100);
        }
        stop(process);
        fail("Token Exchange application did not start: " + Files.readString(log));
        return process;
    }

    private static int availablePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static RequestSpecification request(int port) {
        return RestAssured.given().baseUri("http://localhost").basePath("").port(port)
                .redirects().follow(false);
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
