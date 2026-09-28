package io.quarkiverse.authorization.server.it.dpop;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.function.Supplier;

import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.common.dpop.client.DPoPClient;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** Real grants, JDBC, and quarkus-oidc resource validation, also run against the packaged app. */
@QuarkusTest
public class DPoPTokenExchangeTest {
    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private final DPoPClient client = new DPoPClient();

    @Test
    void tokenExchangeBindsOutputAndPreservesDelegationAndIssuedTokenType() throws Exception {
        String subject = bearerSubject();
        Response actor = client.clientCredentials("machine-jwt").post(TOKEN_ENDPOINT);
        actor.then().statusCode(200);
        for (String id : List.of("machine-jwt", "machine-opaque")) {
            var key = DPoPClient.key();
            Response tokens = client.tokenExchange(id, subject)
                    .formParam("actor_token", actor.<String> path("access_token"))
                    .formParam("actor_token_type", ACCESS_TOKEN_TYPE)
                    .header("DPoP", client.proof(key))
                    .post(TOKEN_ENDPOINT);
            client.assertBound(tokens, key, "resource-owner");
            assertEquals(ACCESS_TOKEN_TYPE, tokens.path("issued_token_type"));
            assertNull(tokens.path("refresh_token"));
            assertEquals(
                    "machine-jwt", client.introspect(tokens.path("access_token")).path("act.sub"));
            Response bearer = client.tokenExchange(id, subject).post(TOKEN_ENDPOINT);
            bearer.then().statusCode(200).body("token_type", equalTo("Bearer"));
            assertNull(client.introspect(bearer.path("access_token")).path("cnf"));
        }
        var key = DPoPClient.key();
        String proof = client.proof(key);
        client.tokenExchange("machine-opaque", subject)
                .formParam("requested_token_type", JWT_TOKEN_TYPE)
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
        Response jwt = client.tokenExchange("machine-jwt", subject)
                .formParam("requested_token_type", JWT_TOKEN_TYPE)
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT);
        client.assertBound(jwt, key, "resource-owner");
        assertEquals(JWT_TOKEN_TYPE, jwt.path("issued_token_type"));
    }

    @Test
    void tokenExchangeAcceptsBoundSubjectOrActorWithOptionalOutputBinding() throws Exception {
        String subject = bearerSubject();
        for (String id : List.of("machine-jwt", "machine-opaque")) {
            var key = DPoPClient.key();
            Response boundSubject = client.tokenExchange(id, subject)
                    .header("DPoP", client.proof(key))
                    .post(TOKEN_ENDPOINT);
            boundSubject.then().statusCode(200);
            String subjectToken = boundSubject.path("access_token");
            assertOptionalExchangeOutputBinding(
                    () -> client.tokenExchange(id, subjectToken), key, null);

            Response boundActor = client.clientCredentials(id)
                    .header("DPoP", client.proof(key))
                    .post(TOKEN_ENDPOINT);
            boundActor.then().statusCode(200);
            String actorToken = boundActor.path("access_token");
            assertOptionalExchangeOutputBinding(
                    () -> client.tokenExchange(id, subject)
                            .formParam("actor_token", actorToken)
                            .formParam("actor_token_type", ACCESS_TOKEN_TYPE),
                    key,
                    id);
            assertEquals(
                    DPoPClient.thumbprint(key), client.introspect(subjectToken).path("cnf.jkt"));
            assertEquals(
                    DPoPClient.thumbprint(key), client.introspect(actorToken).path("cnf.jkt"));
        }
    }

    @Test
    void tokenExchangeAcceptsSubjectAndActorBoundToDifferentKeys() throws Exception {
        String subject = bearerSubject();
        for (String id : List.of("machine-jwt", "machine-opaque")) {
            var subjectKey = DPoPClient.key();
            var actorKey = DPoPClient.key();
            Response boundSubject = client.tokenExchange(id, subject)
                    .header("DPoP", client.proof(subjectKey))
                    .post(TOKEN_ENDPOINT);
            Response boundActor = client.clientCredentials(id)
                    .header("DPoP", client.proof(actorKey))
                    .post(TOKEN_ENDPOINT);
            boundSubject.then().statusCode(200);
            boundActor.then().statusCode(200);
            assertOptionalExchangeOutputBinding(
                    () -> client.tokenExchange(id, boundSubject.path("access_token"))
                            .formParam("actor_token", boundActor.<String> path("access_token"))
                            .formParam("actor_token_type", ACCESS_TOKEN_TYPE),
                    subjectKey,
                    id);
        }
    }

    @Test
    void invalidExchangeInputDoesNotConsumeProof() throws Exception {
        String subject = bearerSubject();
        var key = DPoPClient.key();
        String proof = client.proof(key);
        client.tokenExchange("machine-jwt", "unknown")
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_grant"));
        client.tokenExchange("machine-jwt", subject)
                .formParam("actor_token", "unknown")
                .formParam("actor_token_type", ACCESS_TOKEN_TYPE)
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_grant"));
        client.assertBound(
                client.tokenExchange("machine-jwt", subject)
                        .header("DPoP", proof)
                        .post(TOKEN_ENDPOINT),
                key,
                "resource-owner");
    }

    @Test
    void allThreeGrantsRejectMalformedDuplicateAndWrongTargetProofsBeforeIssuance()
            throws Exception {
        String subject = bearerSubject();
        Response device = client.startDevice("device-jwt");
        client.approveDevice(device, true);
        var key = DPoPClient.key();
        List<Supplier<RequestSpecification>> requests = List.of(
                () -> client.clientCredentials("machine-jwt"),
                () -> client.deviceExchange("device-jwt", device.path("device_code")),
                () -> client.tokenExchange("machine-jwt", subject));
        for (var request : requests) {
            for (String invalid : List.of("", "not-a-jwt", client.proof(key, "POST", "/wrong", null)))
                request.get()
                        .header("DPoP", invalid)
                        .post(TOKEN_ENDPOINT)
                        .then()
                        .statusCode(400)
                        .body("error", equalTo("invalid_dpop_proof"));
            String proof = client.proof(key);
            request.get()
                    .header("DPoP", proof)
                    .header("DPoP", proof)
                    .post(TOKEN_ENDPOINT)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
            request.get()
                    .header("DPoP", proof)
                    .post(TOKEN_ENDPOINT)
                    .then()
                    .statusCode(200)
                    .body("token_type", equalTo("DPoP"));
        }
    }

    @Test
    void tokenEndpointReplayStoreIsSharedAcrossGrantTypes() throws Exception {
        String subject = bearerSubject();
        Response device = client.startDevice("device-jwt");
        client.approveDevice(device, true);
        var key = DPoPClient.key();
        String proof = client.proof(key);
        client.clientCredentials("machine-jwt")
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(200);
        client.tokenExchange("machine-jwt", subject)
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_dpop_proof"));
        client.deviceExchange("device-jwt", device.path("device_code"))
                .header("DPoP", proof)
                .post(TOKEN_ENDPOINT)
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_dpop_proof"));
        client.assertBound(
                client.deviceExchange("device-jwt", device.path("device_code"))
                        .header("DPoP", client.proof(key))
                        .post(TOKEN_ENDPOINT),
                key,
                "resource-owner");
    }

    private void assertOptionalExchangeOutputBinding(
            Supplier<RequestSpecification> exchange, PublicJsonWebKey inputKey, String actor)
            throws Exception {
        // The Token Exchange proof selects the output key independently of input cnf.
        for (var outputKey : List.of(inputKey, DPoPClient.key())) {
            String proof = client.proof(outputKey);
            Response tokens = exchange.get().header("DPoP", proof).post(TOKEN_ENDPOINT);
            client.assertBound(tokens, outputKey, "resource-owner");
            assertEquals(ACCESS_TOKEN_TYPE, tokens.path("issued_token_type"));
            assertEquals(actor, client.introspect(tokens.path("access_token")).path("act.sub"));
            exchange.get()
                    .header("DPoP", proof)
                    .post(TOKEN_ENDPOINT)
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_dpop_proof"));
        }
        Response bearer = exchange.get().post(TOKEN_ENDPOINT);
        bearer.then().statusCode(200).body("token_type", equalTo("Bearer"));
        assertEquals(ACCESS_TOKEN_TYPE, bearer.path("issued_token_type"));
        Response active = client.introspect(bearer.path("access_token"));
        assertEquals(true, active.path("active"));
        assertNull(active.path("cnf"));
        assertEquals(actor, active.path("act.sub"));
    }

    private String bearerSubject() throws Exception {
        return client.exchange("public-jwt", client.code("public-jwt", null), null)
                .then()
                .statusCode(200)
                .extract()
                .path("access_token");
    }
}
