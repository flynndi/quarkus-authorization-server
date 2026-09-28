package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;

class OAuth2TokenRevocationEndpointTest {

    private static final String CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";
    private static final String JWT_CLIENT_SECRET_HASH = BcryptUtil.bcryptHash("jwt-secret");
    private static final String REVOCATION_PATH = "/oauth2/remove";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset("""
                    quarkus.http.root-path=/api
                    quarkus.authorization-server.issuer=https://issuer.example/api
                    quarkus.authorization-server.oidc.enabled=true
                    quarkus.authorization-server.token-revocation-endpoint=/oauth2/remove
                    quarkus.authorization-server.clients.opaque-client.client-secret=%s
                    quarkus.authorization-server.clients.opaque-client.authorization-grant-types=client_credentials
                    quarkus.authorization-server.clients.opaque-client.scopes=message.read
                    quarkus.authorization-server.clients.opaque-client.access-token-format=reference
                    quarkus.authorization-server.clients.jwt-client.client-secret=%s
                    quarkus.authorization-server.clients.jwt-client.authorization-grant-types=client_credentials
                    quarkus.authorization-server.clients.jwt-client.scopes=message.read
                    """.formatted(CLIENT_SECRET_HASH, JWT_CLIENT_SECRET_HASH)), "application.properties"));

    @Test
    void revokesOpaqueTokenAndRepeatedRequestRemainsSuccessful() {
        String token = issueToken("opaque-client", "client-secret");
        introspectionRequest(token).post("/oauth2/introspect").then().statusCode(200)
                .body("active", equalTo(true));

        revocationRequest("opaque-client", "client-secret", token)
                .post(REVOCATION_PATH).then().statusCode(200).body(emptyString());
        introspectionRequest(token).post("/oauth2/introspect").then().statusCode(200)
                .body("active", equalTo(false));

        revocationRequest("opaque-client", "client-secret", token)
                .post(REVOCATION_PATH).then().statusCode(200).body(emptyString());
    }

    @Test
    void revokesJwtAndIgnoresWrongTokenTypeHint() {
        String token = issueToken("jwt-client", "jwt-secret");
        org.junit.jupiter.api.Assertions.assertEquals(3, token.split("\\.").length);

        revocationRequest("jwt-client", "jwt-secret", token)
                .formParam("token_type_hint", "refresh_token")
                .post(REVOCATION_PATH).then().statusCode(200).body(emptyString());
        introspectionRequest(token).post("/oauth2/introspect").then().statusCode(200)
                .body("active", equalTo(false));
    }

    @Test
    void rejectsTokenIssuedToAnotherClientWithoutRevokingIt() {
        String token = issueToken("opaque-client", "client-secret");

        revocationRequest("jwt-client", "jwt-secret", token)
                .post(REVOCATION_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_client"));

        introspectionRequest(token).post("/oauth2/introspect").then().statusCode(200)
                .body("active", equalTo(true));
    }

    @Test
    void unknownTokenAndRepeatedUnknownTokenReturnEmptySuccess() {
        for (int attempt = 0; attempt < 2; attempt++) {
            revocationRequest("opaque-client", "client-secret", "unknown-token")
                    .post(REVOCATION_PATH).then().statusCode(200).body(emptyString());
        }
    }

    @Test
    void validatesFormParametersAndClientAuthentication() {
        revocationRequest("opaque-client", "client-secret", null)
                .post(REVOCATION_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_request"))
                .body("error_description", equalTo("OAuth 2.0 Token Revocation Parameter: token"));
        revocationRequest("opaque-client", "client-secret", "one")
                .formParam("token", "two")
                .post(REVOCATION_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_request"));
        revocationRequest("opaque-client", "client-secret", "token")
                .formParam("token_type_hint", "access_token", "refresh_token")
                .post(REVOCATION_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_request"));

        given().contentType(ContentType.URLENC).formParam("token", "token")
                .post(REVOCATION_PATH).then().statusCode(401)
                .header("WWW-Authenticate", equalTo("Basic realm=\"oauth2/client\""))
                .body("error", equalTo("invalid_client"));
        revocationRequest("opaque-client", "wrong-secret", "token")
                .post(REVOCATION_PATH).then().statusCode(401)
                .body("error", equalTo("invalid_client"));
    }

    @Test
    void customPathRootPathMatcherAndMetadataAgree() {
        for (String metadata : new String[] {
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration" }) {
            given().get(metadata).then().statusCode(200)
                    .body("revocation_endpoint", equalTo("https://issuer.example/api/oauth2/remove"))
                    .body("revocation_endpoint_auth_methods_supported",
                            contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"));
        }
        revocationRequest("opaque-client", "client-secret", "token")
                .post("/oauth2/revoke").then().statusCode(404);
        given().get(REVOCATION_PATH).then().statusCode(404);
        given().auth().preemptive().basic("opaque-client", "client-secret")
                .contentType(ContentType.JSON).body("{\"token\":\"token\"}")
                .post(REVOCATION_PATH).then().statusCode(415);
    }

    private static String issueToken(String clientId, String clientSecret) {
        return given().auth().preemptive().basic(clientId, clientSecret)
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .extract().path("access_token");
    }

    private static RequestSpecification revocationRequest(String clientId, String clientSecret, String token) {
        RequestSpecification request = given().auth().preemptive().basic(clientId, clientSecret)
                .contentType(ContentType.URLENC);
        return token != null ? request.formParam("token", token) : request;
    }

    private static RequestSpecification introspectionRequest(String token) {
        return given().auth().preemptive().basic("jwt-client", "jwt-secret")
                .contentType(ContentType.URLENC).formParam("token", token);
    }
}
