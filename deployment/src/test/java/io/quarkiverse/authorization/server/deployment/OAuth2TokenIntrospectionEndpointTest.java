package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;

class OAuth2TokenIntrospectionEndpointTest {

    private static final String CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";
    private static final String INTROSPECTOR_SECRET_HASH = BcryptUtil.bcryptHash("introspector-secret");
    private static final String INTROSPECTION_PATH = "/oauth2/check_token";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset("""
                    quarkus.http.root-path=/api
                    quarkus.authorization-server.issuer=https://issuer.example/api
                    quarkus.authorization-server.oidc.enabled=true
                    quarkus.authorization-server.token-introspection-endpoint=/oauth2/check_token
                    quarkus.authorization-server.clients.authorized-client.client-secret=%s
                    quarkus.authorization-server.clients.authorized-client.authorization-grant-types=client_credentials
                    quarkus.authorization-server.clients.authorized-client.scopes=message.read
                    quarkus.authorization-server.clients.authorized-client.access-token-format=reference
                    quarkus.authorization-server.clients.introspecting-client.client-secret=%s
                    quarkus.authorization-server.clients.introspecting-client.authorization-grant-types=client_credentials
                    """.formatted(CLIENT_SECRET_HASH, INTROSPECTOR_SECRET_HASH)), "application.properties"));

    @Inject
    OAuth2AuthorizationService authorizations;

    @Test
    void authenticatedClientCanIntrospectAnotherClientsActiveToken() {
        String token = issueOpaqueToken();

        introspectionRequest(token).formParam("token_type_hint", "refresh_token")
                .formParam("custom", "value")
                .post(INTROSPECTION_PATH)
                .then().statusCode(200).contentType(ContentType.JSON)
                .header("Cache-Control", equalTo("no-store"))
                .header("Pragma", equalTo("no-cache"))
                .body("active", equalTo(true))
                .body("client_id", equalTo("authorized-client"))
                .body("token_type", equalTo("Bearer"))
                .body("scope", equalTo("message.read"))
                .body("iss", equalTo("https://issuer.example/api"))
                .body("sub", equalTo("authorized-client"))
                .body("aud", contains("authorized-client"))
                .body("iat", notNullValue())
                .body("exp", notNullValue())
                .body("nbf", notNullValue())
                .body("jti", notNullValue())
                .body("$", not(hasKey("username")));
    }

    @Test
    void inactiveAndUnknownTokensDoNotLeakClaims() {
        introspectionRequest("unknown-token").post(INTROSPECTION_PATH).then().statusCode(200)
                .body("$", aMapWithSize(1)).body("active", equalTo(false));

        String token = issueOpaqueToken();
        OAuth2Authorization authorization = this.authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(authorization);
        this.authorizations.save(OAuth2Authorization.from(authorization)
                .token(authorization.getAccessToken().getToken(), metadata -> metadata.put(
                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
                .build());

        introspectionRequest(token).post(INTROSPECTION_PATH).then().statusCode(200)
                .body("$", aMapWithSize(1)).body("active", equalTo(false));
    }

    @Test
    void consentStateReturnsOnlyActiveFalse() {
        String token = issueOpaqueToken();
        OAuth2Authorization authorization = this.authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        this.authorizations.save(OAuth2Authorization.from(authorization)
                .attribute(OAuth2ParameterNames.STATE, "introspection-consent-state")
                .build());

        introspectionRequest("introspection-consent-state").post(INTROSPECTION_PATH)
                .then().statusCode(200).body("$", aMapWithSize(1)).body("active", equalTo(false));
        introspectionRequest(token).post(INTROSPECTION_PATH)
                .then().statusCode(200).body("active", equalTo(true));
    }

    @Test
    void validatesFormParametersAndClientAuthentication() {
        introspectionRequest(null).post(INTROSPECTION_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_request"))
                .body("error_description", equalTo("OAuth 2.0 Token Introspection Parameter: token"));
        introspectionRequest("one").formParam("token", "two").post(INTROSPECTION_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_request"));
        introspectionRequest("token").formParam("token_type_hint", "access_token", "refresh_token")
                .post(INTROSPECTION_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_request"));

        given().contentType(ContentType.URLENC).formParam("token", "token")
                .post(INTROSPECTION_PATH).then().statusCode(401)
                .header("WWW-Authenticate", equalTo("Basic realm=\"oauth2/client\""))
                .body("error", equalTo("invalid_client"));
        introspectionRequest("token").auth().preemptive().basic("introspecting-client", "wrong-secret")
                .post(INTROSPECTION_PATH).then().statusCode(401)
                .body("error", equalTo("invalid_client"))
                .body("error_description", nullValue());
    }

    @Test
    void customPathRootPathMatcherAndMetadataAgree() {
        for (String metadata : new String[] {
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration" }) {
            given().get(metadata).then().statusCode(200)
                    .body("introspection_endpoint", equalTo("https://issuer.example/api/oauth2/check_token"))
                    .body("introspection_endpoint_auth_methods_supported",
                            contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"));
        }
        given().auth().preemptive().basic("introspecting-client", "introspector-secret")
                .contentType(ContentType.URLENC).formParam("token", "token")
                .post("/oauth2/introspect").then().statusCode(404);
        given().get(INTROSPECTION_PATH).then().statusCode(404);
        given().auth().preemptive().basic("introspecting-client", "introspector-secret")
                .contentType(ContentType.JSON).body("{\"token\":\"token\"}")
                .post(INTROSPECTION_PATH).then().statusCode(415);
    }

    private static String issueOpaqueToken() {
        return given().auth().preemptive().basic("authorized-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .extract().path("access_token");
    }

    private static RequestSpecification introspectionRequest(String token) {
        RequestSpecification request = given().auth().preemptive()
                .basic("introspecting-client", "introspector-secret")
                .contentType(ContentType.URLENC);
        return token != null ? request.formParam("token", token) : request;
    }
}
