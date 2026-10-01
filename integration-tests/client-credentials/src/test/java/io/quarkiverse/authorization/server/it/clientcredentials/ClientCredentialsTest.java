package io.quarkiverse.authorization.server.it.clientcredentials;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;
import io.smallrye.jwt.util.KeyUtils;

/** HTTP-only contract reused against the packaged JVM; no mocked identity, token generator or repository. */
@QuarkusTest
public class ClientCredentialsTest {

    @ParameterizedTest
    @ValueSource(strings = { "jwt-private", "jwt-secret" })
    void jwtClientAuthenticationUsesJdbcSettingsAndAuthorizesOidcResource(String clientId) throws Exception {
        var discovery = given().get("/.well-known/openid-configuration").then().statusCode(200).extract().response();
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(clientId);
        claims.setSubject(clientId);
        claims.setAudience(discovery.<String> path("token_endpoint"));
        claims.setExpirationTimeMinutesInTheFuture(5);
        JsonWebSignature assertion = new JsonWebSignature();
        assertion.setPayload(claims.toJson());
        if ("jwt-private".equals(clientId)) {
            try (var input = ClientCredentialsTest.class.getClassLoader().getResourceAsStream("test-private-key.pem")) {
                String pem = new String(input.readAllBytes(), StandardCharsets.US_ASCII);
                assertion.setKey(KeyUtils.decodePrivateKey(pem));
            }
            assertion.setAlgorithmHeaderValue("RS256");
            assertion.setKeyIdHeaderValue("client-credentials-test-key");
        } else {
            assertion.setAlgorithmHeaderValue("HS256");
            assertion.setKey(new HmacKey("0123456789abcdef".repeat(4).getBytes(StandardCharsets.UTF_8)));
        }
        String token = given().contentType(ContentType.URLENC).formParam("client_id", clientId)
                .formParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .formParam("client_assertion", assertion.getCompactSerialization())
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read").post("/oauth2/token").then().statusCode(200).extract().path("access_token");
        given().auth().oauth2(token).get("/api/messages").then().statusCode(200).body("subject", equalTo(clientId));
    }

    @Test
    void postCredentialsSurviveFormEncodingAndAuthorizeResourceAndTokenLifecycle() {
        String token = ClientCredentialsTest.postClientRequest()
                .formParam("grant_type", "client_credentials").formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200).body("token_type", equalTo("Bearer"))
                .extract().path("access_token");
        given().auth().oauth2(token).get("/api/messages").then().statusCode(200)
                .body("subject", equalTo("post-client"));
        ClientCredentialsTest.postClientRequest()
                .formParam("token", token).post("/oauth2/introspect").then().statusCode(200)
                .body("active", equalTo(true)).body("client_id", equalTo("post-client"));
        ClientCredentialsTest.postClientRequest()
                .formParam("token", token).post("/oauth2/revoke").then().statusCode(200).body(equalTo(""));
        ClientCredentialsTest.postClientRequest()
                .formParam("token", token).post("/oauth2/introspect").then().statusCode(200)
                .body("active", equalTo(false));
        ClientCredentialsTest.postClientRequest()
                .formParam("scope", "message.read").post("/oauth2/device_authorization").then().statusCode(200)
                .body("device_code", notNullValue()).body("user_code", notNullValue());
        given().auth().preemptive().basic("post-client", URLEncoder.encode("post+secret%&=中文", StandardCharsets.UTF_8))
                .contentType(ContentType.URLENC).formParam("grant_type", "client_credentials")
                .post("/oauth2/token").then().statusCode(401).body("error", equalTo("invalid_client"));
    }

    @Test
    void machineTokenAuthorizesResourceThroughOidcDiscovery() {
        var discovery = given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("jwks_uri", endsWith("/oauth2/jwks")).extract().response();
        String token = tokenRequest("machine-client", "machine-secret")
                .formParam("scope", "message.read openid")
                .post(discovery.<String> path("token_endpoint"))
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", equalTo("no-store"))
                .header("Pragma", equalTo("no-cache"))
                .body("token_type", equalTo("Bearer"))
                .body("expires_in", equalTo(120))
                .body("access_token", notNullValue())
                .body("$", not(hasKey("refresh_token")))
                .body("$", not(hasKey("id_token")))
                .extract()
                .path("access_token");

        given().auth().oauth2(token).get("/api/messages").then().statusCode(200)
                .body("subject", equalTo("machine-client"))
                .body("issuer", equalTo(discovery.<String> path("issuer")))
                .body("audience", hasItem("machine-client"));
    }

    @Test
    void missingOrInsufficientScopesAreDeniedByResourceServer() {
        String noScope = tokenRequest("machine-client", "machine-secret")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("$", not(hasKey("scope")))
                .extract()
                .path("access_token");
        given().auth().oauth2(noScope).get("/api/messages").then().statusCode(403);

        String writeOnly = tokenRequest("machine-client", "machine-secret")
                .formParam("scope", "message.write")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .extract()
                .path("access_token");
        given().auth().oauth2(writeOnly).get("/api/messages").then().statusCode(403);
    }

    @Test
    void rejectsClientAndGrantErrorsAsOAuthJson() {
        for (String client : new String[] { "machine-client", "unknown-client", "public-client" }) {
            tokenRequest(client, "wrong-secret")
                    .post("/oauth2/token")
                    .then()
                    .statusCode(401)
                    .contentType(ContentType.JSON)
                    .header("WWW-Authenticate", equalTo("Basic realm=\"oauth2/client\""))
                    .body("error", equalTo("invalid_client"));
        }
        given().contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .post("/oauth2/token")
                .then()
                .statusCode(401)
                .body("error", equalTo("invalid_client"));
        given().contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .formParam("client_id", "public-client")
                .formParam("code", "not-a-code")
                .formParam("code_verifier", "a".repeat(43))
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_client"));
        tokenRequest("legacy-client", "legacy-secret").post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("unauthorized_client"));
        tokenRequest("machine-client", "machine-secret")
                .formParam("scope", "message.admin")
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_scope"));
        tokenRequest("machine-client", "machine-secret")
                .formParam("grant_type", "password")
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
    }

    @Test
    void rejectsTamperedAndMissingBearerTokens() {
        String token = tokenRequest("machine-client", "machine-secret")
                .formParam("scope", "message.read")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .extract()
                .path("access_token");
        given().auth().oauth2(token).get("/api/messages").then().statusCode(200);
        // Keep the JWT structure and claims intact but corrupt the signature.
        String[] segments = token.split("\\.");
        byte[] signature = Base64.getUrlDecoder().decode(segments[2]);
        signature[0] ^= 1;
        String tampered = segments[0] + "." + segments[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        given().auth().oauth2(tampered).get("/api/messages").then().statusCode(401);
        given().get("/api/messages").then().statusCode(401);
    }

    @Test
    void rejectsExpiredTokenAfterAcceptingItBeforeExpiry() throws InterruptedException {
        // Resolve discovery before issuing a short-lived token; startup latency must not consume
        // its lifetime.
        String warmup = tokenRequest("machine-client", "machine-secret")
                .formParam("scope", "message.read")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .extract()
                .path("access_token");
        given().auth().oauth2(warmup).get("/api/messages").then().statusCode(200);
        String token = tokenRequest("short-lived-client", "short-secret")
                .formParam("scope", "message.read")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("expires_in", equalTo(3))
                .extract()
                .path("access_token");
        given().auth().oauth2(token).get("/api/messages").then().statusCode(200);

        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        int status;
        do {
            Thread.sleep(100);
            status = given().auth().oauth2(token).get("/api/messages").statusCode();
            assertTrue(
                    status == 200 || status == 401,
                    "Expected valid or expired token, got " + status);
        } while (status == 200 && System.nanoTime() < deadline);
        assertEquals(401, status, "The real token must expire with lifespan-grace=0");
    }

    @Test
    void discoveryDeclaresOnlyInstalledCapability() {
        for (String path : new String[] {
                "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"
        }) {
            given().get(path)
                    .then()
                    .statusCode(200)
                    .body("token_endpoint", endsWith("/oauth2/token"))
                    .body(
                            "grant_types_supported",
                            containsInAnyOrder(
                                    "password",
                                    "authorization_code",
                                    "refresh_token",
                                    "client_credentials",
                                    "urn:ietf:params:oauth:grant-type:device_code",
                                    "urn:ietf:params:oauth:grant-type:token-exchange"))
                    .body(
                            "introspection_endpoint",
                            equalTo("http://localhost:8081/oauth2/introspect"))
                    .body(
                            "introspection_endpoint_auth_methods_supported",
                            contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                    .body("revocation_endpoint", equalTo("http://localhost:8081/oauth2/revoke"))
                    .body(
                            "revocation_endpoint_auth_methods_supported",
                            contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                    .body(
                            "device_authorization_endpoint",
                            equalTo("http://localhost:8081/oauth2/device_authorization"))
                    .body("$", not(hasKey("registration_endpoint")));
        }
    }

    static RequestSpecification postClientRequest() {
        // RestAssured defaults forms to ISO-8859-1; OAuth form credentials use UTF-8.
        return given().contentType("application/x-www-form-urlencoded; charset=UTF-8")
                .formParam("client_id", "post-client").formParam("client_secret", "post+secret%&=中文");
    }

    static RequestSpecification tokenRequest(String clientId, String secret) {
        return given().auth().preemptive().basic(clientId, secret).contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials");
    }
}
