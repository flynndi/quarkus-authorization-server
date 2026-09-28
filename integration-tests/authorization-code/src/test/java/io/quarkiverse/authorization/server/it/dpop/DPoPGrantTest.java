package io.quarkiverse.authorization.server.it.dpop;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.common.dpop.client.DPoPClient;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;

@QuarkusTest
public class DPoPGrantTest {
    private final DPoPClient client = new DPoPClient();

    @Test
    void publicCodeAndRefreshBindJwtAndOpaqueAcrossJdbcAndConsent() throws Exception {
        for (String id : List.of("public-jwt", "public-opaque")) {
            var key = DPoPClient.key();
            var wrong = DPoPClient.key();
            String code = client.code(id, key);
            client.exchange(id, code, null)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            client.exchange(id, code, client.proof(wrong))
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            String codeProof = client.proof(key);
            client.exchangeRequest(id, code)
                    .header("DPoP", codeProof, codeProof)
                    .post("/oauth2/token")
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            Response tokens = client.exchange(id, code, codeProof);
            client.assertBound(tokens, key, "resource-owner");
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
            client.refresh(id, refresh, codeProof)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            String refreshProof = client.proof(key);
            client.refresh(
                    id.equals("public-jwt") ? "public-opaque" : "public-jwt",
                    refresh,
                    refreshProof)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_grant"));
            client.tokenRequest(id)
                    .formParam("grant_type", "refresh_token")
                    .formParam("refresh_token", refresh)
                    .formParam("scope", "forbidden")
                    .header("DPoP", refreshProof)
                    .post("/oauth2/token")
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_scope"));
            // The same proof remains usable after ownership/scope failures.
            Response next = client.refresh(id, refresh, refreshProof);
            client.assertBound(next, key, "resource-owner");
            String nextRefresh = next.path("refresh_token");
            if (id.equals("public-opaque"))
                assertEquals(refresh, nextRefresh);
            else {
                assertNotEquals(refresh, nextRefresh);
                client.refresh(id, refresh, client.proof(key))
                        .then()
                        .statusCode(400)
                        .body("error", equalTo("invalid_grant"));
            }
            client.refresh(id, nextRefresh, client.proof(wrong))
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
        }
    }

    @Test
    void confidentialRefreshKeepsClientAuthenticationAndAllowsKeyChanges() throws Exception {
        var first = DPoPClient.key();
        var second = DPoPClient.key();
        Response tokens = client.exchange(
                "confidential", client.code("confidential", null), client.proof(first));
        client.assertBound(tokens, first, "resource-owner");
        client.request()
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", "confidential")
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", tokens.<String> path("refresh_token"))
                .header("DPoP", client.proof(first))
                .post("/oauth2/token")
                .then()
                .statusCode(401);
        Response bearer = client.refresh("confidential", tokens.path("refresh_token"), null);
        bearer.then().statusCode(200).body("token_type", equalTo("Bearer"));
        assertNull(client.introspect(bearer.path("access_token")).path("cnf"));
        Response changed = client.refresh("confidential", bearer.path("refresh_token"), client.proof(second));
        client.assertBound(changed, second, "resource-owner");
    }

    @Test
    void publicRefreshRequiresDpopAndRegisteredRefreshGrantWhilePkceRemainsRequired()
            throws Exception {
        Response bearer = client.exchange("public-jwt", client.code("public-jwt", null), null);
        bearer.then().statusCode(200).body("token_type", equalTo("Bearer"));
        assertNull(bearer.path("refresh_token"));
        var key = DPoPClient.key();
        Response noRefresh = client.exchange(
                "public-no-refresh",
                client.code("public-no-refresh", key),
                client.proof(key));
        client.assertBound(noRefresh, key, "resource-owner");
        assertNull(noRefresh.path("refresh_token"));
        String code = client.code("public-jwt", key);
        client.tokenRequest("public-jwt")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", DPoPClient.REDIRECT)
                .formParam("code_verifier", "wrong")
                .header("DPoP", client.proof(key))
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_grant"));
        client.assertBound(
                client.exchange("public-jwt", code, client.proof(key)), key, "resource-owner");
    }

    @Test
    void pkceFailuresDoNotConsumeDpopProofForPublicOrConfidentialClients() throws Exception {
        for (String id : List.of("public-jwt", "public-opaque", "confidential")) {
            var key = DPoPClient.key();
            String code = client.code(id, key);
            String proof = client.proof(key);
            for (String kind : List.of("missing", "wrong", "duplicate", "blank")) {
                var request = client.tokenRequest(id)
                        .formParam("grant_type", "authorization_code")
                        .formParam("code", code)
                        .formParam("redirect_uri", DPoPClient.REDIRECT)
                        .header("DPoP", proof);
                if (kind.equals("wrong"))
                    request.formParam("code_verifier", "wrong");
                if (kind.equals("duplicate"))
                    request.formParam("code_verifier", "one", "two");
                if (kind.equals("blank"))
                    request.formParam("code_verifier", " ");
                request.post("/oauth2/token")
                        .then()
                        .statusCode(400)
                        .body(
                                "error",
                                equalTo(
                                        kind.equals("duplicate") || kind.equals("blank")
                                                ? "invalid_request"
                                                : "invalid_grant"));
            }
            client.assertBound(client.exchange(id, code, proof), key, "resource-owner");
        }
    }

    @Test
    void malformedOrDuplicateCodeThumbprintsAreRejectedBeforeCodeIssuance() throws Exception {
        for (Object[] values : List.of(
                new Object[] { "" },
                new Object[] { "bad" },
                new Object[] { "a".repeat(43), "b".repeat(43) })) {
            Response response = client.authorization("public-jwt", client.login())
                    .queryParam("dpop_jkt", values)
                    .get("/oauth2/authorize")
                    .then()
                    .statusCode(302)
                    .extract()
                    .response();
            assertEquals("invalid_request", DPoPClient.query(response.header("Location"), "error"));
        }
    }

    @Test
    void tokenExchangeAllowsBearerOutputWhileUserInfoRequiresBoundProof() throws Exception {
        var key = DPoPClient.key();
        Response bound = client.exchange("public-jwt", client.code("public-jwt", key), client.proof(key));
        bound.then().statusCode(200);
        String access = bound.path("access_token");
        client.request()
                .header("Authorization", "Bearer " + access)
                .get("/userinfo")
                .then()
                .statusCode(401);
        client.request()
                .header("Authorization", "DPoP " + access)
                .header("DPoP", client.proof(key, "GET", "/userinfo", access))
                .get("/userinfo")
                .then()
                .statusCode(200)
                .body("sub", equalTo("resource-owner"));
        Response bearer = client.exchange("confidential", client.code("confidential", null), null);
        bearer.then().statusCode(200);
        String unbound = bearer.path("access_token");
        for (boolean actor : List.of(false, true)) {
            var exchange = client.request()
                    .auth()
                    .preemptive()
                    .basic("dpop-resource-server", "resource-secret")
                    .contentType("application/x-www-form-urlencoded")
                    .formParam(
                            "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                    .formParam("subject_token", actor ? unbound : access)
                    .formParam(
                            "subject_token_type",
                            "urn:ietf:params:oauth:token-type:access_token");
            if (actor)
                exchange.formParam("actor_token", access)
                        .formParam(
                                "actor_token_type",
                                "urn:ietf:params:oauth:token-type:access_token");
            Response exchanged = exchange.post("/oauth2/token");
            exchanged
                    .then()
                    .statusCode(200)
                    .body("token_type", equalTo("Bearer"));
            Response active = client.introspect(exchanged.path("access_token"));
            assertEquals(true, active.path("active"));
            assertNull(active.path("cnf"));
            assertEquals(actor ? "resource-owner" : null, active.path("act.sub"));
        }
        client.request()
                .auth()
                .preemptive()
                .basic("dpop-resource-server", "resource-secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .header("DPoP", client.proof(key))
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_dpop_proof"));
    }
}
