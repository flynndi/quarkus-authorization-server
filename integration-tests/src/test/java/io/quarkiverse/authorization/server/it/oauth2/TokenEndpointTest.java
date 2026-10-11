package io.quarkiverse.authorization.server.it.oauth2;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.config.AuthorizationServerPersistence;
import io.quarkiverse.authorization.server.it.support.OAuthRequests;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;

/** Runs unchanged against the packaged JVM application and native executable. */
@QuarkusTest
public class TokenEndpointTest {

    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    @Test
    void clientCredentialsTokenAuthenticatesToTheResourceServer() {
        String token = OAuthRequests.client().formParam("grant_type", "client_credentials")
                .formParam("scope", "securityIdentity jsonWebToken").post("/oauth2/token")
                .then().statusCode(200).body("token_type", equalTo("Bearer"))
                .body("expires_in", greaterThan(0)).body("refresh_token", nullValue()).extract().path("access_token");

        RestAssured.given().auth().oauth2(token).get("/api/resource/jsonWebToken")
                .then().statusCode(200).body("subject", equalTo(AuthorizationServerPersistence.CLIENT_ID));
    }

    @Test
    void passwordTokenContainsUserRolesAndCanBeRefreshedThroughJdbc() {
        var tokens = OAuthRequests.userTokens("securityIdentity jsonWebToken");
        tokens.then().body("refresh_token", notNullValue());
        RestAssured.given().auth().oauth2(tokens.path("access_token")).get("/api/resource/jsonWebToken")
                .then().statusCode(200).body("subject", equalTo("admin")).body("groups", hasItem("admin"))
                .body("keySet()", containsInAnyOrder("subject", "issuer", "groups"));

        String refreshed = OAuthRequests.client().formParam("grant_type", "refresh_token")
                .formParam("refresh_token", tokens.<String> path("refresh_token"))
                .formParam("scope", "securityIdentity").post("/oauth2/token")
                .then().statusCode(200).body("scope", equalTo("securityIdentity")).extract().path("access_token");

        RestAssured.given().auth().oauth2(refreshed).get("/api/resource/securityIdentity")
                .then().statusCode(200).body("name", equalTo("admin")).body("roles", hasItem("admin"))
                .body("keySet()", containsInAnyOrder("name", "roles"));
        RestAssured.given().auth().oauth2(refreshed).get("/api/resource/jsonWebToken").then().statusCode(403);
    }

    @Test
    void rejectsInvalidClientCredentials() {
        RestAssured.given().auth().preemptive().basic(AuthorizationServerPersistence.CLIENT_ID, "wrong-secret")
                .formParam("grant_type", "client_credentials").post("/oauth2/token")
                .then().statusCode(401).body("error", equalTo("invalid_client"));
    }

    @Test
    void rejectsInvalidResourceOwnerCredentials() {
        OAuthRequests.password("admin", "wrong-password", "securityIdentity").post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("invalid_grant"));
        OAuthRequests.password("missing-user", "password", "securityIdentity").post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("invalid_grant"));
    }

    @Test
    void rejectsUnregisteredScopes() {
        OAuthRequests.client().formParam("grant_type", "client_credentials")
                .formParam("scope", "unregistered.scope").post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("invalid_scope"));
    }

    @Test
    void rejectsRefreshScopeEscalation() {
        var tokens = OAuthRequests.userTokens("securityIdentity");
        OAuthRequests.client().formParam("grant_type", "refresh_token")
                .formParam("refresh_token", tokens.<String> path("refresh_token"))
                .formParam("scope", "jsonWebToken").post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("invalid_scope"));
    }

    @Test
    void tokenExchangePreservesTheUserAndNarrowsScopes() {
        String subject = OAuthRequests.userTokens("securityIdentity jsonWebToken").path("access_token");
        String exchanged = TokenEndpointTest.exchange(subject).formParam("scope", "jsonWebToken")
                .post("/oauth2/token").then().statusCode(200)
                .body("issued_token_type", equalTo(ACCESS_TOKEN_TYPE)).body("scope", equalTo("jsonWebToken"))
                .extract().path("access_token");

        RestAssured.given().auth().oauth2(exchanged).get("/api/resource/jsonWebToken")
                .then().statusCode(200).body("subject", equalTo("admin")).body("groups", hasItem("admin"));
        RestAssured.given().auth().oauth2(exchanged).get("/api/resource/securityIdentity").then().statusCode(403);
    }

    @Test
    void rejectsUnknownTokenExchangeSubject() {
        TokenEndpointTest.exchange("missing-subject-token").post("/oauth2/token")
                .then().statusCode(400).body("error", equalTo("invalid_grant"));
    }

    @Test
    void introspectionObservesRevocation() {
        String token = OAuthRequests.userTokens("securityIdentity").path("access_token");
        OAuthRequests.client().formParam("token", token).post("/oauth2/introspect")
                .then().statusCode(200).body("active", equalTo(true)).body("sub", equalTo("admin"));
        OAuthRequests.client().formParam("token", token).post("/oauth2/revoke").then().statusCode(200);
        OAuthRequests.client().formParam("token", token).post("/oauth2/introspect")
                .then().statusCode(200).body("active", equalTo(false));
    }

    private static RequestSpecification exchange(String subjectToken) {
        return OAuthRequests.client().formParam("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                .formParam("subject_token", subjectToken).formParam("subject_token_type", ACCESS_TOKEN_TYPE);
    }
}
