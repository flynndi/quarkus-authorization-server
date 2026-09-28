package io.quarkiverse.authorization.server.it.multipleissuers;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** Restarts a packaged process over two independent file H2 databases and stable test signing keys. */
class MultipleIssuersJdbcRestartIT {
    @TempDir
    Path directory;

    @Test
    void restoresBothIssuersWithoutSharingCodesRefreshOrPushedRequests() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        Process process = this.start(port, "first");
        try {
            var cookies = MultipleIssuersJdbcRestartIT.request(port).formParam("j_username", "alice")
                    .formParam("j_password", "password")
                    .post("/j_security_check").then().statusCode(302).extract().cookies();
            String alphaCode = MultipleIssuersJdbcRestartIT.authorize(port, "alpha", cookies);
            String betaCode = MultipleIssuersJdbcRestartIT.authorize(port, "beta", cookies);
            var betaTokens = MultipleIssuersJdbcRestartIT.exchange(port, "beta", betaCode).then().statusCode(200).extract()
                    .response();
            String betaAccess = betaTokens.path("access_token"), betaRefresh = betaTokens.path("refresh_token");
            String par = MultipleIssuersJdbcRestartIT.request(port).auth().preemptive().basic("shared", "alpha-secret")
                    .formParam("response_type", "code").formParam("client_id", "shared")
                    .formParam("redirect_uri", MultipleIssuersHttpTest.REDIRECT)
                    .formParam("scope", "openid alpha").formParam("code_challenge", MultipleIssuersHttpTest.CHALLENGE)
                    .formParam("code_challenge_method", "S256").post("/alpha/oauth2/par").then().statusCode(201).extract()
                    .path("request_uri");
            MultipleIssuersJdbcRestartIT.stop(process);
            process = this.start(port, "second");
            MultipleIssuersJdbcRestartIT.request(port).auth().oauth2(betaAccess).get("/beta/message").then().statusCode(200)
                    .body("subject", equalTo("alice"));
            MultipleIssuersJdbcRestartIT.request(port).auth().oauth2(betaAccess).get("/alpha/message").then().statusCode(401);
            MultipleIssuersJdbcRestartIT.exchange(port, "beta", alphaCode).then().statusCode(400).body("error",
                    equalTo("invalid_grant"));
            String alphaAccess = MultipleIssuersJdbcRestartIT.exchange(port, "alpha", alphaCode).then().statusCode(200)
                    .extract().path("access_token");
            MultipleIssuersJdbcRestartIT.request(port).auth().oauth2(alphaAccess).get("/alpha/message").then().statusCode(200)
                    .body("subject", equalTo("alice"));
            MultipleIssuersJdbcRestartIT.request(port).auth().preemptive().basic("shared", "alpha-secret")
                    .formParam("grant_type", "refresh_token").formParam("refresh_token", betaRefresh).post("/alpha/token")
                    .then().statusCode(400).body("error", equalTo("invalid_grant"));
            String refreshed = MultipleIssuersJdbcRestartIT.request(port).auth().preemptive().basic("shared", "beta-secret")
                    .formParam("grant_type", "refresh_token").formParam("refresh_token", betaRefresh).post("/beta/token")
                    .then().statusCode(200).extract().path("access_token");
            MultipleIssuersJdbcRestartIT.request(port).auth().oauth2(refreshed).get("/beta/message").then().statusCode(200);
            MultipleIssuersJdbcRestartIT.request(port).cookies(cookies).queryParam("client_id", "shared")
                    .queryParam("request_uri", par)
                    .get("/beta/authorize").then().statusCode(400);
            var restored = MultipleIssuersJdbcRestartIT.request(port).cookies(cookies).queryParam("client_id", "shared")
                    .queryParam("request_uri", par)
                    .get("/alpha/authorize").then().statusCode(302).extract().response();
            String restoredCode = MultipleIssuersHttpTest.query(restored.header("Location"), "code");
            MultipleIssuersJdbcRestartIT.exchange(port, "alpha", restoredCode).then().statusCode(200);
            MultipleIssuersJdbcRestartIT.request(port).cookies(cookies).queryParam("client_id", "shared")
                    .queryParam("request_uri", par)
                    .get("/alpha/authorize").then().statusCode(400);
        } finally {
            MultipleIssuersJdbcRestartIT.stop(process);
        }
    }

    private static String authorize(int port, String tenant, Map<String, String> cookies) {
        var consent = MultipleIssuersJdbcRestartIT.request(port).cookies(cookies).queryParam("response_type", "code")
                .queryParam("client_id", "shared").queryParam("redirect_uri", MultipleIssuersHttpTest.REDIRECT)
                .queryParam("scope", "openid " + tenant).queryParam("code_challenge", MultipleIssuersHttpTest.CHALLENGE)
                .queryParam("code_challenge_method", "S256").get("/" + tenant + "/authorize").then().statusCode(200).extract()
                .response();
        String state = consent.htmlPath().getString("**.find { it.@name == 'state' }.@value");
        var response = MultipleIssuersJdbcRestartIT.request(port).cookies(cookies).formParam("client_id", "shared")
                .formParam("state", state).formParam("scope", tenant).formParam("consent_action", "approve")
                .post("/" + tenant + "/authorize")
                .then().statusCode(302).extract().response();
        return MultipleIssuersHttpTest.query(response.header("Location"), "code");
    }

    private static Response exchange(int port, String tenant, String code) {
        return MultipleIssuersJdbcRestartIT.request(port).auth().preemptive().basic("shared", tenant + "-secret")
                .formParam("grant_type", "authorization_code").formParam("code", code)
                .formParam("redirect_uri", MultipleIssuersHttpTest.REDIRECT)
                .formParam("code_verifier", MultipleIssuersHttpTest.VERIFIER).post("/" + tenant + "/token");
    }

    private Process start(int port, String run) throws Exception {
        Path build = Path.of("build").toAbsolutePath();
        Properties artifact = new Properties();
        try (var input = Files.newInputStream(build.resolve("quarkus-artifact.properties"))) {
            artifact.load(input);
        }
        boolean nativeImage = "native".equals(artifact.getProperty("type"));
        Path application = build.resolve(artifact.getProperty("path"));
        List<String> command = new ArrayList<>();
        command.add(nativeImage ? application.toString() : Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-Dquarkus.http.port=" + port);
        for (String tenant : List.of("alpha", "beta")) {
            command.add("-Dquarkus.authorization-server.issuers." + tenant + "=http://localhost:" + port + "/server/" + tenant);
            command.add("-Dquarkus.datasource." + tenant + ".jdbc.url=jdbc:h2:file:" + this.directory.resolve(tenant)
                    + ";DB_CLOSE_ON_EXIT=FALSE");
        }
        if (!nativeImage) {
            command.add("-jar");
            command.add(application.toString());
        }
        Path log = this.directory.resolve(run + ".log");
        Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        long deadline = System.nanoTime() + Duration.ofSeconds(40).toNanos();
        while (process.isAlive() && System.nanoTime() < deadline) {
            try {
                if (MultipleIssuersJdbcRestartIT.request(port).get("/alpha/.well-known/openid-configuration")
                        .statusCode() == 200)
                    return process;
            } catch (Exception ignored) {
                /* Wait for the real listener and initialized issuer components. */ }
            Thread.sleep(100);
        }
        MultipleIssuersJdbcRestartIT.stop(process);
        fail("Application did not start: " + Files.readString(log));
        return process;
    }

    private static RequestSpecification request(int port) {
        return RestAssured.given().baseUri("http://localhost").basePath("/server").port(port).redirects().follow(false);
    }

    private static void stop(Process process) throws InterruptedException {
        if (process != null && process.isAlive()) {
            process.destroy();
            if (!process.waitFor(10, TimeUnit.SECONDS))
                process.destroyForcibly().waitFor(10, TimeUnit.SECONDS);
        }
    }
}
