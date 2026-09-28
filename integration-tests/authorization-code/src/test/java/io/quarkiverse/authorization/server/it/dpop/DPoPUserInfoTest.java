package io.quarkiverse.authorization.server.it.dpop;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.common.dpop.client.DPoPClient;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;

/** Production authorization-code issuance, JDBC loading and Quarkus HTTP authentication. */
@QuarkusTest
public class DPoPUserInfoTest {
    private final DPoPClient client = new DPoPClient();

    @Test
    void servesJwtAndReferenceOnGetAndPostAndStillAcceptsUnboundBearer() throws Exception {
        for (String id : List.of("public-jwt", "public-opaque")) {
            var key = DPoPClient.key();
            String access = tokens(id, key).path("access_token");
            for (String method : List.of("GET", "POST")) {
                userInfo(access, client.proof(key, method, "/userinfo", access), method)
                        .then()
                        .statusCode(200)
                        .contentType("application/json")
                        .header("Cache-Control", equalTo("no-store"))
                        .body("sub", equalTo("resource-owner"))
                        .body("$", not(hasKey("iss")))
                        .body("$", not(hasKey("aud")))
                        .body("$", not(hasKey("cnf")));
            }
            client.request()
                    .header("Authorization", "dPoP   " + access)
                    .header("DPoP", client.proof(key, "GET", "/userinfo", access))
                    .get("/userinfo?ignored=value")
                    .then()
                    .statusCode(200);
        }
        String bearer = client.exchange("public-jwt", client.code("public-jwt", null), null)
                .then()
                .statusCode(200)
                .extract()
                .path("access_token");
        client.request()
                .header("Authorization", "Bearer " + bearer)
                .get("/userinfo")
                .then()
                .statusCode(200)
                .body("sub", equalTo("resource-owner"));
        client.request()
                .get("/userinfo")
                .then()
                .statusCode(401)
                .header("WWW-Authenticate", equalTo("Bearer, DPoP algs=\"ES256 RS256\""));
    }

    @Test
    void rejectsMissingMalformedDuplicateAndInvalidProofsWithDpopChallenges() throws Exception {
        for (String id : List.of("public-jwt", "public-opaque")) {
            var key = DPoPClient.key();
            String access = tokens(id, key).path("access_token");
            error(userInfo(access, null, "GET"), "invalid_dpop_proof");
            for (String proof : List.of(
                    "",
                    "not-a-proof",
                    client.proof(key, "GET", "/userinfo", null),
                    client.proof(key, "GET", "/userinfo", "another-token"),
                    client.proof(key, "POST", "/userinfo", access),
                    client.proof(key, "GET", "/other", access),
                    client.proof(
                            key,
                            "GET",
                            "/userinfo",
                            access,
                            claims -> claims.put(
                                    "iat",
                                    Instant.now()
                                            .minusSeconds(120)
                                            .getEpochSecond())),
                    client.proof(
                            key,
                            "GET",
                            "/userinfo",
                            access,
                            claims -> claims.remove("jti")))) {
                error(userInfo(access, proof, "GET"), "invalid_dpop_proof");
            }
            error(
                    userInfo(
                            access,
                            client.proof(DPoPClient.key(), "GET", "/userinfo", access),
                            "GET"),
                    "invalid_token");
            String valid = client.proof(key, "GET", "/userinfo", access);
            // A signature with another public key advertised must fail before replay registration.
            String other = client.proof(DPoPClient.key(), "GET", "/userinfo", access);
            String badSignature = valid.substring(0, valid.lastIndexOf('.') + 1)
                    + other.substring(other.lastIndexOf('.') + 1);
            error(userInfo(access, badSignature, "GET"), "invalid_dpop_proof");
            client.request()
                    .header("Authorization", "DPoP " + access)
                    .header("DPoP", valid, valid)
                    .get("/userinfo")
                    .then()
                    .statusCode(401)
                    .body("error", equalTo("invalid_dpop_proof"));
            client.request()
                    .header("Authorization", "DPoP " + access, "Bearer " + access)
                    .header("DPoP", valid)
                    .get("/userinfo")
                    .then()
                    .statusCode(400)
                    .header("WWW-Authenticate", containsString("Bearer"))
                    .header("WWW-Authenticate", containsString("DPoP"))
                    .body("error", equalTo("invalid_request"));
            userInfo(access, valid, "GET").then().statusCode(200);
            error(userInfo(access, valid, "GET"), "invalid_dpop_proof");
        }
    }

    @Test
    void preventsTokenSubstitutionAndBearerDowngradeWithoutConsumingValidProof() throws Exception {
        var key = DPoPClient.key();
        String first = tokens("public-jwt", key).path("access_token");
        String second = tokens("public-opaque", key).path("access_token");
        String proof = client.proof(key, "GET", "/userinfo", first);
        error(userInfo(second, proof, "GET"), "invalid_dpop_proof");
        error(userInfo("unknown", proof, "GET"), "invalid_token");
        for (boolean withProof : List.of(false, true)) {
            var request = client.request().header("Authorization", "Bearer " + first);
            if (withProof)
                request.header("DPoP", proof);
            request.get("/userinfo")
                    .then()
                    .statusCode(401)
                    .header("WWW-Authenticate", equalTo("Bearer error=\"invalid_token\""))
                    .body("error", equalTo("invalid_token"));
        }
        userInfo(first, proof, "GET").then().statusCode(200);
        String bearer = client.exchange("public-jwt", client.code("public-jwt", null), null)
                .then()
                .statusCode(200)
                .extract()
                .path("access_token");
        error(
                userInfo(bearer, client.proof(key, "GET", "/userinfo", bearer), "GET"),
                "invalid_token");
    }

    @Test
    void rechecksCurrentTokenScopeAndRevocationAfterAuthentication() throws Exception {
        for (String id : List.of("public-jwt", "public-opaque")) {
            var key = DPoPClient.key();
            Response initial = tokens(id, key);
            String oldAccess = initial.path("access_token");
            Response narrowed = client.refresh(id, initial.path("refresh_token"), client.proof(key));
            narrowed.then().statusCode(200);
            String access = narrowed.path("access_token");
            error(
                    userInfo(oldAccess, client.proof(key, "GET", "/userinfo", oldAccess), "GET"),
                    "invalid_token");
            for (String method : List.of("GET", "POST")) {
                userInfo(access, client.proof(key, method, "/userinfo", access), method)
                        .then()
                        .statusCode(403)
                        .header(
                                "WWW-Authenticate",
                                equalTo("DPoP algs=\"ES256 RS256\", error=\"insufficient_scope\""))
                        .body("error", equalTo("insufficient_scope"));
            }
        }
        var key = DPoPClient.key();
        String access = tokens("confidential", key).path("access_token");
        userInfo(access, client.proof(key, "GET", "/userinfo", access), "GET")
                .then()
                .statusCode(200);
        client.request()
                .auth()
                .preemptive()
                .basic("confidential", "confidential-secret")
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", access)
                .post("/oauth2/revoke")
                .then()
                .statusCode(200);
        error(
                userInfo(access, client.proof(key, "GET", "/userinfo", access), "GET"),
                "invalid_token");
    }

    @Test
    void concurrentRequestsCanConsumeTheSameProofOnlyOnce() throws Exception {
        var key = DPoPClient.key();
        String access = tokens("public-opaque", key).path("access_token");
        String proof = client.proof(key, "GET", "/userinfo", access);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(4)) {
            List<Future<Response>> responses = new ArrayList<>();
            for (int i = 0; i < 4; i++)
                responses.add(
                        executor.submit(
                                () -> {
                                    assertTrue(start.await(10, TimeUnit.SECONDS));
                                    return userInfo(access, proof, "GET");
                                }));
            start.countDown();
            int accepted = 0;
            for (var future : responses) {
                Response response = future.get(20, TimeUnit.SECONDS);
                if (response.statusCode() == 200)
                    accepted++;
                else
                    error(response, "invalid_dpop_proof");
            }
            assertEquals(1, accepted);
        }
    }

    private Response tokens(String id, PublicJsonWebKey key) throws Exception {
        return client.exchange(id, client.code(id, key), client.proof(key))
                .then()
                .statusCode(200)
                .extract()
                .response();
    }

    private Response userInfo(String access, String proof, String method) {
        var request = client.request().header("Authorization", "DPoP " + access);
        if (proof != null)
            request.header("DPoP", proof);
        return request.request(method, "/userinfo");
    }

    private static void error(Response response, String code) {
        response.then()
                .statusCode(401)
                .contentType("application/json")
                .header("Cache-Control", equalTo("no-store"))
                .header(
                        "WWW-Authenticate",
                        equalTo("DPoP algs=\"ES256 RS256\", error=\"" + code + "\""))
                .body("error", equalTo(code));
    }
}
