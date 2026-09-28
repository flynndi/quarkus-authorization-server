package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import java.util.List;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionAuthenticationRequest;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;

class JwtClientAuthenticationTest {
    static final String SECRET = "0123456789abcdef".repeat(4);
    static final String ISSUER = "https://issuer.example/api";
    private static final String TOKEN = "/assertion/token";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withApplicationRoot(jar -> jar
            .addClass(ClientAssertionTestSupport.class)
            .addAsResource("privateKey.pem").addAsResource("publicKey.pem")
            .addAsResource(new StringAsset(
                    """
                            quarkus.http.root-path=/api
                            quarkus.authorization-server.issuer=https://issuer.example/api
                            quarkus.authorization-server.token-endpoint=/assertion/token
                            quarkus.authorization-server.oidc.enabled=true
                            quarkus.authorization-server.pushed-authorization-requests-enabled=true
                            quarkus.authorization-server.signing.key-id=assertion-test-key
                            quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                            quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                            quarkus.authorization-server.clients.jwt-private.client-authentication-methods=private_key_jwt
                            quarkus.authorization-server.clients.jwt-private.jwk-set-url=http://localhost:8081/api/oauth2/jwks
                            quarkus.authorization-server.clients.jwt-private.token-endpoint-authentication-signing-algorithm=RS256
                            quarkus.authorization-server.clients.jwt-private.authorization-grant-types=client_credentials,urn:ietf:params:oauth:grant-type:device_code,authorization_code
                            quarkus.authorization-server.clients.jwt-private.redirect-uris=https://client.example/callback
                            quarkus.authorization-server.clients.jwt-private.scopes=message.read
                            quarkus.authorization-server.clients.jwt-secret.client-authentication-methods=client_secret_jwt
                            quarkus.authorization-server.clients.jwt-secret.client-secret=%s
                            quarkus.authorization-server.clients.jwt-secret.token-endpoint-authentication-signing-algorithm=HS256
                            quarkus.authorization-server.clients.jwt-secret.authorization-grant-types=client_credentials,urn:ietf:params:oauth:grant-type:device_code,authorization_code
                            quarkus.authorization-server.clients.jwt-secret.redirect-uris=https://client.example/callback
                            quarkus.authorization-server.clients.jwt-secret.scopes=message.read
                            """
                            .formatted(SECRET)),
                    "application.properties"));

    @ParameterizedTest
    @ValueSource(strings = { "jwt-private", "jwt-secret" })
    void authenticatesAtAllFiveEndpointsWithRootPathAndCustomTokenPath(String clientId) throws Exception {
        String token = JwtClientAuthenticationTest.request(clientId).formParam("grant_type", "client_credentials")
                .formParam("scope", "message.read").post(TOKEN).then().statusCode(200)
                .body("token_type", equalTo("Bearer")).extract().path("access_token");
        JwtClientAuthenticationTest.request(clientId).formParam("token", token).post("/oauth2/introspect")
                .then().statusCode(200).body("active", equalTo(true)).body("client_id", equalTo(clientId));
        JwtClientAuthenticationTest.request(clientId).formParam("token", token).post("/oauth2/revoke")
                .then().statusCode(200).body(equalTo(""));
        JwtClientAuthenticationTest.request(clientId).formParam("token", token).post("/oauth2/introspect")
                .then().statusCode(200).body("active", equalTo(false));
        JwtClientAuthenticationTest.request(clientId).formParam("scope", "message.read").post("/oauth2/device_authorization")
                .then().statusCode(200).body("device_code", notNullValue());
        given().contentType(ContentType.URLENC).formParam("client_id", clientId)
                .formParam("client_assertion_type", JwtClientAssertionAuthenticationRequest.ASSERTION_TYPE)
                .formParam("client_assertion", ClientAssertionTestSupport.assertion(clientId,
                        clientId.equals("jwt-secret") ? SECRET : null, ISSUER + "/oauth2/par", "assertion-test-key"))
                .formParam("response_type", "code").formParam("redirect_uri", "https://client.example/callback")
                .formParam("scope", "message.read").formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .formParam("code_challenge_method", "S256")
                .post("/oauth2/par").then().statusCode(201)
                .body("request_uri", notNullValue());
    }

    @Test
    void rejectsWrongAudienceClientBindingAndUnsupportedAssertionType() throws Exception {
        String wrongAudience = ClientAssertionTestSupport.assertion("jwt-secret", SECRET, "https://other.example", null);
        given().contentType(ContentType.URLENC).formParam("client_id", "jwt-secret")
                .formParam("client_assertion_type", JwtClientAssertionAuthenticationRequest.ASSERTION_TYPE)
                .formParam("client_assertion", wrongAudience).post(TOKEN).then().statusCode(401)
                .body("error", equalTo("invalid_client"));
        String valid = ClientAssertionTestSupport.assertion("jwt-secret", SECRET, ISSUER, null);
        for (String client : List.of("jwt-private", "unknown-client")) {
            given().contentType(ContentType.URLENC).formParam("client_id", client)
                    .formParam("client_assertion_type", JwtClientAssertionAuthenticationRequest.ASSERTION_TYPE)
                    .formParam("client_assertion", valid).post(TOKEN).then().statusCode(401)
                    .body("error", equalTo("invalid_client"));
        }
        given().contentType(ContentType.URLENC).formParam("client_id", "jwt-secret")
                .formParam("client_assertion_type", "unsupported").formParam("client_assertion", valid)
                .post(TOKEN).then().statusCode(401).body("error", equalTo("invalid_client"));
    }

    @Test
    void rejectsMissingBlankAndRepeatedAssertionParametersWithoutFallingBack() throws Exception {
        for (String parameter : List.of("client_id", "client_assertion", "client_assertion_type")) {
            for (String shape : List.of("missing", "blank", "repeated")) {
                var parameters = new java.util.LinkedHashMap<String, Object>();
                parameters.put("client_id", "jwt-secret");
                parameters.put("client_assertion", ClientAssertionTestSupport.assertion("jwt-secret", SECRET, ISSUER, null));
                parameters.put("client_assertion_type", JwtClientAssertionAuthenticationRequest.ASSERTION_TYPE);
                if ("missing".equals(shape))
                    parameters.remove(parameter);
                if ("blank".equals(shape))
                    parameters.put(parameter, " ");
                if ("repeated".equals(shape))
                    parameters.put(parameter, List.of(parameters.get(parameter), parameters.get(parameter)));
                given().contentType(ContentType.URLENC).formParams(parameters).post(TOKEN).then()
                        .statusCode(400).body("error", equalTo("invalid_request"));
            }
        }
        JwtClientAuthenticationTest.request("jwt-secret").formParam("client_secret", SECRET).post(TOKEN)
                .then().statusCode(400).body("error", equalTo("invalid_request"));
    }

    @Test
    void discoveryPublishesAssertionAlgorithmsSeparatelyFromServerTokenSigningKeys() {
        for (String endpoint : List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")) {
            var response = given().get(endpoint).then().statusCode(200);
            for (String name : List.of("token", "introspection", "revocation")) {
                response.body(name + "_endpoint_auth_signing_alg_values_supported", containsInAnyOrder(
                        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "HS256", "HS384",
                        "HS512"));
            }
        }
    }

    private static RequestSpecification request(String clientId) throws Exception {
        boolean sharedSecret = "jwt-secret".equals(clientId);
        return given().contentType(ContentType.URLENC).formParam("client_id", clientId)
                .formParam("client_assertion_type", JwtClientAssertionAuthenticationRequest.ASSERTION_TYPE)
                .formParam("client_assertion", ClientAssertionTestSupport.assertion(clientId,
                        sharedSecret ? SECRET : null, ISSUER + TOKEN, "assertion-test-key"));
    }

}
