package io.quarkiverse.authorization.server.it.registration;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;

/** Every target client is registered through HTTP; no CDI/database shortcuts or fixed client IDs. */
@QuarkusTest
public class OidcClientRegistrationTest {
    @Test
    void dynamicPublicAndConfidentialClientsCompleteOidcCodePkce() throws Exception {
        var http = new ClientRegistrationRequests(RestAssured.port);
        for (boolean publicClient : new boolean[] { true, false }) {
            String initial = initial(publicClient ? "public" : "confidential");
            var registration = http.register(initial, publicClient);
            if (publicClient) {
                assertNull(registration.path("client_secret"));
                assertNull(registration.path("client_secret_expires_at"));
            } else {
                assertNotNull(registration.path("client_secret"));
                assertEquals(0, registration.<Integer> path("client_secret_expires_at"));
            }
            http.read(registration);
            var registrationClaims = http.verifyJwt(registration.path("registration_access_token"));
            assertEquals(List.of("client.read"), registrationClaims.get("scope"));
            assertEquals(registration.path("client_id"), registrationClaims.get("sub"));
            assertEquals(List.of(registration.<String> path("client_id")), registrationClaims.get("aud"));
            http.post(initial, Map.of("redirect_uris", List.of(ClientRegistrationRequests.REDIRECT)))
                    .then().statusCode(401).body("error", equalTo("invalid_token"));

            String code = http.authorize(registration, "dynamic-registration-nonce");
            var tokens = http.exchange(registration, code).then().statusCode(200).extract().response();
            var claims = http.verifyJwt(tokens.path("id_token"));
            assertEquals("dynamic-registration-nonce", claims.get("nonce"));
            assertEquals("resource-owner", claims.get("sub"));
            assertEquals(List.of(registration.<String> path("client_id")), claims.get("aud"));
            String access = tokens.path("access_token");
            if (publicClient) {
                assertNull(tokens.path("refresh_token"));
            } else {
                tokens = http.clientRequest(registration).contentType(ContentType.URLENC)
                        .formParam("grant_type", "refresh_token")
                        .formParam("refresh_token", tokens.<String> path("refresh_token"))
                        .post(http.endpoint("token_endpoint")).then().statusCode(200).extract().response();
                assertFalse(http.verifyJwt(tokens.path("id_token")).containsKey("nonce"));
                access = tokens.path("access_token");
            }
            http.request().header("Authorization", "Bearer " + access).get(http.endpoint("userinfo_endpoint"))
                    .then().statusCode(200).body("sub", equalTo("resource-owner"));
            http.request().header("Authorization", "Bearer " + tokens.<String> path("id_token"))
                    .get(registration.<String> path("registration_client_uri")).then().statusCode(401)
                    .body("error", equalTo("invalid_token"));
        }
    }

    @Test
    void rejectsMetadataEscalationAndEnforcesControlScopesAndBinding() {
        var http = new ClientRegistrationRequests(RestAssured.port);
        for (String scenario : List.of("expired", "invalidated", "mixed-scope")) {
            http.post(initial(scenario), Map.of("redirect_uris", List.of(ClientRegistrationRequests.REDIRECT)))
                    .then().statusCode(401).body("error", equalTo("invalid_token"));
        }
        http.post(initial("wrong-scope"), Map.of("redirect_uris", List.of(ClientRegistrationRequests.REDIRECT)))
                .then().statusCode(403).body("error", equalTo("insufficient_scope"));
        for (Map<String, Object> metadata : List.<Map<String, Object>> of(
                Map.of("client_id", "attacker"), Map.of("client_id", "attacker", "client_secret", "attacker"),
                Map.of("scope", "client.create"),
                Map.of("scope", "client.read"), Map.of("token_endpoint_auth_method", "private_key_jwt"),
                Map.of("registration_access_token", "attacker"), Map.of("jwks_uri", "https://untrusted.invalid/jwks"))) {
            var request = new java.util.LinkedHashMap<>(metadata);
            request.put("redirect_uris", List.of(ClientRegistrationRequests.REDIRECT));
            http.post(initial("security"), request).then().statusCode(400).body("error", equalTo("invalid_client_metadata"));
        }
        // The registration builder rejects a secret without a client ID before service validation.
        http.post(initial("security"),
                Map.of("redirect_uris", List.of(ClientRegistrationRequests.REDIRECT), "client_secret", "attacker"))
                .then().statusCode(400).body("error", equalTo("invalid_request"));
        http.post(initial("security"),
                "{\"redirect_uris\":[\"https://rp.example/callback\"],\"scope\":\"openid\",\"scope\":\"client.create\"}")
                .then().statusCode(400).body("error", equalTo("invalid_request"));
        // The same initial token remains usable after rejected input.
        var registration = http.register(initial("security"), false);
        String token = registration.path("registration_access_token");
        http.post(token, Map.of("redirect_uris", List.of(ClientRegistrationRequests.REDIRECT)))
                .then().statusCode(403).body("error", equalTo("insufficient_scope"));
        for (String client : List.of("registration-bootstrap", "missing")) {
            http.request().header("Authorization", "Bearer " + token).queryParam("client_id", client)
                    .get(http.endpoint("registration_endpoint")).then().statusCode(401)
                    .body("error", equalTo("invalid_client"));
        }
        http.request().header("Authorization", "Bearer " + token).get(http.endpoint("userinfo_endpoint"))
                .then().statusCode(403).body("error", equalTo("insufficient_scope"));
        http.read(registration);
    }

    @Test
    void requiresBearerAndDoesNotExposeBootstrapOrManagementEndpoints() {
        var http = new ClientRegistrationRequests(RestAssured.port);
        http.request().contentType(ContentType.JSON).body("{}").post(http.endpoint("registration_endpoint"))
                .then().statusCode(401).header("WWW-Authenticate", equalTo("Bearer"));
        http.request().queryParam("access_token", initial("public")).get(http.endpoint("registration_endpoint"))
                .then().statusCode(401);
        http.request().header("Authorization", "Bearer unknown").get(http.endpoint("registration_endpoint"))
                .then().statusCode(401).contentType(ContentType.JSON).body("error", equalTo("invalid_token"));
        for (String method : List.of("PUT", "DELETE")) {
            http.request().request(method, http.endpoint("registration_endpoint")).then().statusCode(404);
        }
        http.request().post("/bootstrap").then().statusCode(404);
        http.request().header("Authorization", "Bearer unknown").get("/unrelated")
                .then().statusCode(200).body(equalTo("unaffected"));
    }

    private static String initial(String scenario) {
        return "registration-test-only-" + scenario;
    }
}
