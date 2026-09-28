package io.quarkiverse.authorization.server.it.dpop;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.common.dpop.client.DPoPClient;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;

/** Real grants, JDBC, and quarkus-oidc resource validation, also run against the packaged app. */
@QuarkusTest
public class DPoPDeviceTest {
    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private final DPoPClient client = new DPoPClient();

    @Test
    void publicDeviceBindsRefreshAcrossRotationAndReuseForBothFormats() throws Exception {
        for (String id : List.of("device-jwt", "device-opaque")) {
            var key = DPoPClient.key();
            var wrong = DPoPClient.key();
            Response device = client.startDevice(id);
            String code = device.path("device_code");
            String proof = client.proof(key);
            // Polling before approval must not reserve a proof or pin the eventual token key.
            client.deviceExchange(id, code)
                    .header("DPoP", proof)
                    .post(TOKEN_ENDPOINT)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("authorization_pending"));
            client.approveDevice(device, true);
            Response tokens = client.deviceExchange(id, code).header("DPoP", proof).post(TOKEN_ENDPOINT);
            client.assertBound(tokens, key, "resource-owner");
            assertNull(tokens.path("id_token"));
            String refresh = tokens.path("refresh_token");
            assertNotNull(refresh);
            client.refresh(id, refresh, null)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            client.refresh(id, refresh, client.proof(wrong))
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            String refreshProof = client.proof(key);
            client.refresh(
                    id.equals("device-jwt") ? "device-opaque" : "device-jwt",
                    refresh,
                    refreshProof)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_grant"));
            Response next = client.refresh(id, refresh, refreshProof);
            client.assertBound(next, key, "resource-owner");
            String nextRefresh = next.path("refresh_token");
            if (id.equals("device-opaque"))
                assertEquals(refresh, nextRefresh);
            else {
                assertNotEquals(refresh, nextRefresh);
                client.refresh(id, refresh, client.proof(key))
                        .then()
                        .statusCode(400)
                        .body("error", equalTo("invalid_grant"));
            }
            client.refresh(id, nextRefresh, refreshProof)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            client.refresh(id, nextRefresh, client.proof(wrong))
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            client.assertBound(
                    client.refresh(id, nextRefresh, client.proof(key)), key, "resource-owner");
            client.deviceExchange(id, code)
                    .header("DPoP", client.proof(key))
                    .post(TOKEN_ENDPOINT)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("access_denied"));
        }
    }

    @Test
    void publicDeviceWithoutProofOrRefreshRegistrationReceivesNoRefresh() throws Exception {
        Response device = client.startDevice("device-jwt");
        client.approveDevice(device, true);
        Response bearer = client.deviceExchange("device-jwt", device.path("device_code"))
                .post(TOKEN_ENDPOINT);
        bearer.then().statusCode(200).body("token_type", equalTo("Bearer"));
        assertNull(bearer.path("refresh_token"));
        assertNull(client.introspect(bearer.path("access_token")).path("cnf"));
        device = client.startDevice("device-no-refresh");
        client.approveDevice(device, true);
        var key = DPoPClient.key();
        Response bound = client.deviceExchange("device-no-refresh", device.path("device_code"))
                .header("DPoP", client.proof(key))
                .post(TOKEN_ENDPOINT);
        client.assertBound(bound, key, "resource-owner");
        assertNull(bound.path("refresh_token"));
    }

    @Test
    void confidentialDeviceRefreshRemainsClientAuthenticatedAndAllowsOptionalProof()
            throws Exception {
        Response device = client.startDevice("device-confidential");
        client.approveDevice(device, true);
        var key = DPoPClient.key();
        Response tokens = client.deviceExchange("device-confidential", device.path("device_code"))
                .header("DPoP", client.proof(key))
                .post(TOKEN_ENDPOINT);
        client.assertBound(tokens, key, "resource-owner");
        client.request()
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", "device-confidential")
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", tokens.<String> path("refresh_token"))
                .header("DPoP", client.proof(key))
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(401);
        Response bearer = client.refresh("device-confidential", tokens.path("refresh_token"), null);
        bearer.then().statusCode(200).body("token_type", equalTo("Bearer"));
        assertNull(client.introspect(bearer.path("access_token")).path("cnf"));
        var nextKey = DPoPClient.key();
        client.assertBound(
                client.refresh(
                        "device-confidential", bearer.path("refresh_token"), client.proof(nextKey)),
                nextKey,
                "resource-owner");
    }

    @Test
    void deniedDeviceCannotIssueTokensOrConsumeProof() throws Exception {
        Response device = client.startDevice("device-jwt");
        client.approveDevice(device, false);
        var key = DPoPClient.key();
        String proof = client.proof(key);
        client.deviceExchange("device-jwt", device.path("device_code"))
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(400)
                .body("error", equalTo("access_denied"));
        client.assertBound(
                client.clientCredentials("machine-jwt").header("DPoP", proof).post(TOKEN_ENDPOINT),
                key,
                "machine-jwt");
    }
}
