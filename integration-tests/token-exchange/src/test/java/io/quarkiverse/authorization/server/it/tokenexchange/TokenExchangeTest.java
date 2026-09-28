package io.quarkiverse.authorization.server.it.tokenexchange;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

/** HTTP-only Token Exchange contract, reused unchanged against the packaged JVM application. */
@QuarkusTest
public class TokenExchangeTest {

    static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

    @Test
    void verifiesImpersonationDelegationAndMultiLevelActorJwtClaims() {
        String subject = password(TokenExchangeServerConfig.SUBJECT_CLIENT,
                TokenExchangeServerConfig.SUBJECT_SECRET);
        String impersonated = exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, subject, JWT_TOKEN_TYPE)
                .formParam("requested_token_type", JWT_TOKEN_TYPE)
                .formParam("audience", "messages-api")
                .formParam("audience", "audit-api")
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .body("issued_token_type", equalTo(JWT_TOKEN_TYPE))
                .extract().path("access_token");
        assertJwt(impersonated);
        resource(impersonated).then().statusCode(200)
                .body("subject", equalTo(TokenExchangeServerConfig.RESOURCE_OWNER))
                .body("audience", hasItems("messages-api", "audit-api"))
                .body("format", equalTo("self-contained"))
                .body("$", not(hasKey("act")));

        String delegatedSubject = password(TokenExchangeServerConfig.DELEGATED_SUBJECT_CLIENT,
                TokenExchangeServerConfig.DELEGATED_SUBJECT_SECRET);
        String actor = clientCredentials(TokenExchangeServerConfig.ACTOR_CLIENT,
                TokenExchangeServerConfig.ACTOR_SECRET);
        String delegated = exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, delegatedSubject, JWT_TOKEN_TYPE)
                .formParam("actor_token", actor)
                .formParam("actor_token_type", JWT_TOKEN_TYPE)
                .formParam("requested_token_type", JWT_TOKEN_TYPE)
                .formParam("audience", "messages-api")
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .extract().path("access_token");
        resource(delegated).then().statusCode(200)
                .body("subject", equalTo(TokenExchangeServerConfig.RESOURCE_OWNER))
                .body("act.sub", equalTo(TokenExchangeServerConfig.ACTOR_CLIENT));

        String secondActor = clientCredentials(TokenExchangeServerConfig.SECOND_ACTOR_CLIENT,
                TokenExchangeServerConfig.SECOND_ACTOR_SECRET);
        String multiLevel = exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, delegated, JWT_TOKEN_TYPE)
                .formParam("actor_token", secondActor)
                .formParam("actor_token_type", JWT_TOKEN_TYPE)
                .formParam("requested_token_type", JWT_TOKEN_TYPE)
                .formParam("audience", "messages-api")
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .extract().path("access_token");
        resource(multiLevel).then().statusCode(200)
                .body("subject", equalTo(TokenExchangeServerConfig.RESOURCE_OWNER))
                .body("act.sub", equalTo(TokenExchangeServerConfig.SECOND_ACTOR_CLIENT))
                .body("act.act.sub", equalTo(TokenExchangeServerConfig.ACTOR_CLIENT));

        introspect(subject).then().statusCode(200).body("active", equalTo(true));
        introspect(actor).then().statusCode(200).body("active", equalTo(true));
        introspect(delegated).then().statusCode(200).body("active", equalTo(true));
    }

    @Test
    void usesOpaqueIntrospectionAndObservesRevocation() {
        String subject = password(TokenExchangeServerConfig.REFERENCE_SUBJECT_CLIENT,
                TokenExchangeServerConfig.REFERENCE_SUBJECT_SECRET);
        String actor = clientCredentials(TokenExchangeServerConfig.ACTOR_CLIENT,
                TokenExchangeServerConfig.ACTOR_SECRET);
        assertOpaque(subject);

        String exchanged = exchange(TokenExchangeServerConfig.REFERENCE_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.REFERENCE_EXCHANGE_SECRET, subject, ACCESS_TOKEN_TYPE)
                .formParam("actor_token", actor)
                .formParam("actor_token_type", JWT_TOKEN_TYPE)
                .formParam("audience", "messages-api")
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .body("issued_token_type", equalTo(ACCESS_TOKEN_TYPE))
                .extract().path("access_token");
        assertOpaque(exchanged);
        introspect(exchanged).then().statusCode(200)
                .body("active", equalTo(true))
                .body("sub", equalTo(TokenExchangeServerConfig.RESOURCE_OWNER))
                .body("aud", hasItem("messages-api"))
                .body("act.sub", equalTo(TokenExchangeServerConfig.ACTOR_CLIENT));
        resource(exchanged).then().statusCode(200)
                .body("subject", equalTo(TokenExchangeServerConfig.RESOURCE_OWNER))
                .body("format", equalTo("reference"));

        revoke(TokenExchangeServerConfig.REFERENCE_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.REFERENCE_EXCHANGE_SECRET, exchanged)
                .then().statusCode(200);
        introspect(exchanged).then().statusCode(200).body("active", equalTo(false));
        resource(exchanged).then().statusCode(401);
        introspect(subject).then().statusCode(200).body("active", equalTo(true));
        introspect(actor).then().statusCode(200).body("active", equalTo(true));
    }

    @Test
    void rejectsInvalidSubjectActorPolicyScopeGrantAndTokenTypes() throws InterruptedException {
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, "unknown-subject", ACCESS_TOKEN_TYPE),
                "invalid_grant");

        String subject = password(TokenExchangeServerConfig.SUBJECT_CLIENT,
                TokenExchangeServerConfig.SUBJECT_SECRET);
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, subject, ACCESS_TOKEN_TYPE)
                .formParam("actor_token", "unknown-actor")
                .formParam("actor_token_type", ACCESS_TOKEN_TYPE), "invalid_grant");

        String delegatedSubject = password(TokenExchangeServerConfig.DELEGATED_SUBJECT_CLIENT,
                TokenExchangeServerConfig.DELEGATED_SUBJECT_SECRET);
        String wrongActor = clientCredentials(TokenExchangeServerConfig.WRONG_ACTOR_CLIENT,
                TokenExchangeServerConfig.WRONG_ACTOR_SECRET);
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, delegatedSubject, JWT_TOKEN_TYPE)
                .formParam("actor_token", wrongActor)
                .formParam("actor_token_type", JWT_TOKEN_TYPE), "invalid_grant");

        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, subject, JWT_TOKEN_TYPE)
                .formParam("scope", "admin"), "invalid_scope");
        assertError(exchange(TokenExchangeServerConfig.ACTOR_CLIENT,
                TokenExchangeServerConfig.ACTOR_SECRET, subject, JWT_TOKEN_TYPE), "unauthorized_client");
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, subject, "urn:example:token-type"),
                "unsupported_token_type");

        String referenceSubject = password(TokenExchangeServerConfig.REFERENCE_SUBJECT_CLIENT,
                TokenExchangeServerConfig.REFERENCE_SUBJECT_SECRET);
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, referenceSubject, JWT_TOKEN_TYPE),
                "invalid_request");
        assertError(exchange(TokenExchangeServerConfig.REFERENCE_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.REFERENCE_EXCHANGE_SECRET, subject, JWT_TOKEN_TYPE)
                .formParam("requested_token_type", JWT_TOKEN_TYPE), "invalid_request");

        String revokedSubject = password(TokenExchangeServerConfig.SUBJECT_CLIENT,
                TokenExchangeServerConfig.SUBJECT_SECRET);
        revoke(TokenExchangeServerConfig.SUBJECT_CLIENT, TokenExchangeServerConfig.SUBJECT_SECRET,
                revokedSubject).then().statusCode(200);
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, revokedSubject, JWT_TOKEN_TYPE), "invalid_grant");

        String activeSubject = password(TokenExchangeServerConfig.SUBJECT_CLIENT,
                TokenExchangeServerConfig.SUBJECT_SECRET);
        String revokedActor = clientCredentials(TokenExchangeServerConfig.ACTOR_CLIENT,
                TokenExchangeServerConfig.ACTOR_SECRET);
        revoke(TokenExchangeServerConfig.ACTOR_CLIENT, TokenExchangeServerConfig.ACTOR_SECRET,
                revokedActor).then().statusCode(200);
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, activeSubject, JWT_TOKEN_TYPE)
                .formParam("actor_token", revokedActor)
                .formParam("actor_token_type", JWT_TOKEN_TYPE), "invalid_grant");

        String expiredSubject = password(TokenExchangeServerConfig.SHORT_SUBJECT_CLIENT,
                TokenExchangeServerConfig.SHORT_SUBJECT_SECRET);
        String expiredActor = clientCredentials(TokenExchangeServerConfig.SHORT_ACTOR_CLIENT,
                TokenExchangeServerConfig.SHORT_ACTOR_SECRET);
        awaitInactive(expiredSubject);
        awaitInactive(expiredActor);
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, expiredSubject, JWT_TOKEN_TYPE), "invalid_grant");
        assertError(exchange(TokenExchangeServerConfig.JWT_EXCHANGE_CLIENT,
                TokenExchangeServerConfig.JWT_EXCHANGE_SECRET, activeSubject, JWT_TOKEN_TYPE)
                .formParam("actor_token", expiredActor)
                .formParam("actor_token_type", JWT_TOKEN_TYPE), "invalid_grant");
    }

    static String password(String clientId, String secret) {
        return client(clientId, secret).contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", TokenExchangeServerConfig.RESOURCE_OWNER)
                .formParam("password", TokenExchangeServerConfig.RESOURCE_OWNER_PASSWORD)
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .extract().path("access_token");
    }

    static String clientCredentials(String clientId, String secret) {
        return client(clientId, secret).contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .post("/oauth2/token").then().statusCode(200)
                .extract().path("access_token");
    }

    static RequestSpecification exchange(String clientId, String secret, String subjectToken,
            String subjectTokenType) {
        return client(clientId, secret).contentType(ContentType.URLENC)
                .formParam("grant_type", TOKEN_EXCHANGE_GRANT)
                .formParam("subject_token", subjectToken)
                .formParam("subject_token_type", subjectTokenType);
    }

    static Response introspect(String token) {
        return client("resource-server", "resource-secret").contentType(ContentType.URLENC)
                .formParam("token", token).post("/oauth2/introspect");
    }

    static Response revoke(String clientId, String secret, String token) {
        return client(clientId, secret).contentType(ContentType.URLENC)
                .formParam("token", token).post("/oauth2/revoke");
    }

    static Response resource(String token) {
        return io.restassured.RestAssured.given()
                .header("Authorization", "Bearer " + token)
                .get("/api/messages");
    }

    private static RequestSpecification client(String clientId, String secret) {
        return io.restassured.RestAssured.given().auth().preemptive().basic(clientId, secret);
    }

    private static void assertError(RequestSpecification request, String error) {
        request.post("/oauth2/token").then().statusCode(400).body("error", equalTo(error));
    }

    private static void awaitInactive(String token) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        boolean active;
        do {
            active = Boolean.TRUE.equals(introspect(token).then().statusCode(200).extract().path("active"));
            if (active) {
                Thread.sleep(100);
            }
        } while (active && System.nanoTime() < deadline);
        assertFalse(active, "Token did not expire within the test deadline");
    }

    private static void assertJwt(String token) {
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);
    }

    private static void assertOpaque(String token) {
        assertNotNull(token);
        assertFalse(token.contains("."));
    }
}
