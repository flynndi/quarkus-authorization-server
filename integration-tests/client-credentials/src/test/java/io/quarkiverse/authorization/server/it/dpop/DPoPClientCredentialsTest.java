package io.quarkiverse.authorization.server.it.dpop;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.common.dpop.client.DPoPClient;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;

/** Real grants, JDBC, and quarkus-oidc resource validation, also run against the packaged app. */
@QuarkusTest
public class DPoPClientCredentialsTest {
    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private final DPoPClient client = new DPoPClient();

    @Test
    void bothMetadataEndpointsAdvertiseDefaultProofAlgorithms() {
        for (String path : List.of("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
            client.request().get(path).then().statusCode(200)
                    .body("dpop_signing_alg_values_supported", contains("ES256", "RS256"));
        }
    }

    @Test
    void clientCredentialsSupportsOptionalBindingForJwtAndReference() throws Exception {
        for (String id : List.of("machine-jwt", "machine-opaque")) {
            var key = DPoPClient.key();
            Response tokens = client.clientCredentials(id)
                    .header("DPoP", client.proof(key))
                    .post(TOKEN_ENDPOINT);
            client.assertBound(tokens, key, id);
            assertNull(tokens.path("refresh_token"));
            assertNull(tokens.path("id_token"));
            Response bearer = client.clientCredentials(id).post(TOKEN_ENDPOINT);
            bearer.then().statusCode(200).body("token_type", equalTo("Bearer"));
            assertNull(client.introspect(bearer.path("access_token")).path("cnf"));
        }
    }

    @Test
    void clientAuthenticationAndScopeChecksPrecedeProofConsumption() throws Exception {
        var key = DPoPClient.key();
        String proof = client.proof(key);
        client.tokenRequest("device-jwt")
                .formParam("grant_type", "client_credentials")
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_client"));
        client.tokenRequest("machine-jwt")
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "forbidden")
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_scope"));
        client.assertBound(
                client.clientCredentials("machine-jwt").header("DPoP", proof).post(TOKEN_ENDPOINT),
                key,
                "machine-jwt");
    }

    @Test
    void concurrentProofReuseIssuesExactlyOneClientCredentialsToken() throws Exception {
        String proof = client.proof(DPoPClient.key());
        var requests = java.util.stream.IntStream.range(0, 4)
                .mapToObj(
                        i -> CompletableFuture.supplyAsync(
                                () -> client.clientCredentials("machine-jwt")
                                        .header("DPoP", proof)
                                        .post(TOKEN_ENDPOINT)))
                .toList();
        var responses = requests.stream().map(CompletableFuture::join).toList();
        assertEquals(1, responses.stream().filter(r -> r.statusCode() == 200).count());
        responses.stream()
                .filter(r -> r.statusCode() != 200)
                .forEach(
                        r -> r.then().statusCode(400).body("error", equalTo("invalid_dpop_proof")));
    }
}
