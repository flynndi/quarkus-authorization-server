package io.quarkiverse.authorization.server.it.authorizationcode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.ServerSocket;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.restassured.RestAssured;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** Restarts a real packaged process over the same file-backed H2 database, on JVM and native. */
class OidcJdbcRestartIT {
    private static final String CLIENT = "authorization-code-confidential-client";
    private static final String SECRET = "authorization-code-client-secret";
    private static final String REDIRECT = "http://localhost:5173/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @TempDir
    Path directory;

    @Test
    void restoresAuthorizationSessionIdTokenAndRefreshAfterProcessRestart() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        Process process = start(port, "first");
        try {
            Map<String, String> cookies = request(port).contentType("application/x-www-form-urlencoded")
                    .formParam("j_username", "resource-owner").formParam("j_password", "resource-owner-password")
                    .post("/j_security_check").then().statusCode(302).extract().cookies();
            Response authorization = request(port).cookies(cookies).queryParam("response_type", "code")
                    .queryParam("client_id", CLIENT).queryParam("redirect_uri", REDIRECT)
                    .queryParam("scope", "openid profile").queryParam("nonce", "restart-nonce")
                    .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                    .queryParam("code_challenge_method", "S256").get("/oauth2/authorize")
                    .then().statusCode(302).extract().response();
            String code = java.util.Arrays.stream(URI.create(authorization.header("Location")).getRawQuery().split("&"))
                    .filter(part -> part.startsWith("code="))
                    .map(part -> URLDecoder.decode(part.substring(5), StandardCharsets.UTF_8))
                    .findFirst().orElseThrow();
            Response tokens = request(port).auth().preemptive().basic(CLIENT, SECRET)
                    .contentType("application/x-www-form-urlencoded").formParam("grant_type", "authorization_code")
                    .formParam("code", code).formParam("redirect_uri", REDIRECT).formParam("code_verifier", VERIFIER)
                    .post("/oauth2/token").then().statusCode(200).extract().response();
            Map<String, Object> id = claims(tokens.path("id_token"));
            assertNotNull(id.get("sid"));
            assertNotNull(id.get("auth_time"));
            String pushedUri = OidcJdbcRestartIT.request(port).auth().preemptive().basic(CLIENT, SECRET)
                    .contentType("application/x-www-form-urlencoded").formParam("response_type", "code")
                    .formParam("client_id", CLIENT)
                    .formParam("redirect_uri", REDIRECT).formParam("scope", "openid message.read")
                    .formParam("state", "par-restart")
                    .formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                    .formParam("code_challenge_method", "S256").post("/oauth2/par")
                    .then().statusCode(201).extract().path("request_uri");
            stop(process);
            // Provision an initial access token directly in the same JDBC store while the process is stopped.
            // This is test setup, not a public bootstrap endpoint or an open-registration configuration.
            String initial = this.initialRegistrationToken();
            process = start(port, "second");
            var registration = OidcJdbcRestartIT.request(port).auth().oauth2(initial).contentType("application/json")
                    .body(Map.of("grant_types", List.of("client_credentials"))).post("/oauth2/register")
                    .then().statusCode(201).extract().response();
            String registeredClientId = registration.path("client_id"), registeredSecret = registration.path("client_secret");
            stop(process);
            process = start(port, "third");
            String registeredToken = OidcJdbcRestartIT.request(port).auth().preemptive()
                    .basic(registeredClientId, registeredSecret)
                    .formParam("grant_type", "client_credentials").post("/oauth2/token")
                    .then().statusCode(200).extract().path("access_token");
            OidcJdbcRestartIT.request(port).auth().preemptive().basic(registeredClientId, registeredSecret)
                    .formParam("token", registeredToken).post("/oauth2/introspect").then().statusCode(200)
                    .body("active", org.hamcrest.Matchers.equalTo(true));
            OidcJdbcRestartIT.request(port).auth().oauth2(initial).contentType("application/json")
                    .body(Map.of("grant_types", List.of("client_credentials"))).post("/oauth2/register").then().statusCode(401);

            Response restored = OidcJdbcRestartIT.request(port).cookies(cookies).queryParam("client_id", CLIENT)
                    .queryParam("request_uri", pushedUri).get("/oauth2/authorize").then().statusCode(302)
                    .header("Location", org.hamcrest.Matchers.containsString("state=par-restart")).extract().response();
            String restoredCode = java.util.Arrays.stream(URI.create(restored.header("Location")).getRawQuery().split("&"))
                    .filter(part -> part.startsWith("code="))
                    .map(part -> URLDecoder.decode(part.substring(5), StandardCharsets.UTF_8))
                    .findFirst().orElseThrow();
            String parToken = OidcJdbcRestartIT.request(port).auth().preemptive().basic(CLIENT, SECRET)
                    .contentType("application/x-www-form-urlencoded").formParam("grant_type", "authorization_code")
                    .formParam("code", restoredCode).formParam("redirect_uri", REDIRECT).formParam("code_verifier", VERIFIER)
                    .post("/oauth2/token").then().statusCode(200).extract().path("access_token");
            OidcJdbcRestartIT.request(port).auth().oauth2(parToken).get("/api/messages").then().statusCode(200);
            OidcJdbcRestartIT.request(port).cookies(cookies).queryParam("client_id", CLIENT)
                    .queryParam("request_uri", pushedUri)
                    .get("/oauth2/authorize").then().statusCode(400);

            Response userInfo = request(port).header("Authorization", "Bearer " + tokens.<String> path("access_token"))
                    .get("/userinfo").then().statusCode(200).extract().response();
            assertEquals("resource-owner", userInfo.path("sub"));
            Response refreshed = request(port).auth().preemptive().basic(CLIENT, SECRET)
                    .contentType("application/x-www-form-urlencoded").formParam("grant_type", "refresh_token")
                    .formParam("refresh_token", tokens.<String> path("refresh_token"))
                    .post("/oauth2/token").then().statusCode(200).extract().response();
            Map<String, Object> refreshedId = claims(refreshed.path("id_token"));
            assertEquals(id.get("auth_time"), refreshedId.get("auth_time"));
            assertEquals(id.get("sid"), refreshedId.get("sid"));
            assertFalse(refreshedId.containsKey("nonce"));
            Response logout = request(port).cookies(cookies)
                    .queryParam("id_token_hint", refreshed.<String> path("id_token")).queryParam("client_id", CLIENT)
                    .queryParam("post_logout_redirect_uri", "http://localhost:5173/").get("/connect/logout")
                    .then().statusCode(302).extract().response();
            assertEquals("http://localhost:5173/", logout.header("Location"));
            assertEquals(0, logout.getDetailedCookie("quarkus-credential").getMaxAge());
            assertEquals(0, logout.getDetailedCookie("quarkus-credential.oidc").getMaxAge());
        } finally {
            stop(process);
        }
    }

    private String initialRegistrationToken() throws Exception {
        try (var dataSource = io.agroal.api.AgroalDataSource
                .from(new io.agroal.api.configuration.supplier.AgroalDataSourceConfigurationSupplier()
                        .connectionPoolConfiguration(pool -> pool.maxSize(1).connectionFactoryConfiguration(factory -> factory
                                .jdbcUrl("jdbc:h2:file:" + this.directory.resolve("authorization") + ";DB_CLOSE_ON_EXIT=FALSE")
                                .connectionProviderClassName("org.h2.Driver")
                                .principal(new io.agroal.api.security.NamePrincipal("sa"))
                                .credential(new io.agroal.api.security.SimplePassword("sa")))))) {
            var clients = new io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository(dataSource);
            var authorizations = new io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService(
                    dataSource, clients);
            var client = clients.findByClientId(CLIENT);
            String token = java.util.UUID.randomUUID().toString();
            authorizations.save(
                    io.quarkiverse.authorization.server.authorization.OAuth2Authorization.withRegisteredClient(client)
                            .principalName(client.getClientId())
                            .authorizationGrantType(
                                    io.quarkiverse.authorization.server.model.AuthorizationGrantType.CLIENT_CREDENTIALS)
                            .authorizedScopes(java.util.Set.of("client.create"))
                            .accessToken(new io.quarkiverse.authorization.server.token.OAuth2AccessToken(
                                    io.quarkiverse.authorization.server.token.OAuth2AccessToken.TokenType.BEARER, token,
                                    java.time.Instant.now(), java.time.Instant.now().plusSeconds(300),
                                    java.util.Set.of("client.create")))
                            .build());
            return token;
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
        return RestAssured.given().baseUri("http://localhost").basePath("").port(port).redirects().follow(false);
    }

    private static Map<String, Object> claims(String token) {
        return new JsonPath(new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8))
                .getMap("$");
    }
}
