package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.util.Arrays;
import java.util.List;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.security.Authenticated;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import io.restassured.http.Headers;
import io.smallrye.mutiny.Uni;

class OAuth2ClientAuthenticationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(
                            ApplicationEndpoint.class,
                            ApplicationIdentityProvider.class)
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.http.auth.basic=true
                                                    quarkus.authorization-server.issuer=https://issuer.example
                                                    quarkus.authorization-server.clients.oauth-client.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                                    quarkus.authorization-server.clients.oauth-client.authorization-grant-types=password
                                                    quarkus.authorization-server.clients.oauth-client.scopes=message.read,message.write
                                                    quarkus.authorization-server.clients.post-client.client-secret=%s
                                                    quarkus.authorization-server.clients.post-client.client-authentication-methods=client_secret_post
                                                    quarkus.authorization-server.clients.post-client.authorization-grant-types=client_credentials,urn:ietf:params:oauth:grant-type:device_code
                                                    quarkus.authorization-server.clients.post-client.scopes=message.read
                                                    quarkus.authorization-server.clients.public-client.client-authentication-methods=none
                                                    quarkus.authorization-server.clients.public-client.authorization-grant-types=authorization_code,refresh_token,password,client_credentials,urn:ietf:params:oauth:grant-type:token-exchange
                                                    quarkus.authorization-server.clients.public-client.redirect-uris=https://client.example/callback
                                                    quarkus.authorization-server.clients.public-client.scopes=message.read
                                                    """
                                                    .formatted(BcryptUtil.bcryptHash("client-secret", 4))),
                                    "application.properties"));

    @Test
    void clientSecretBasicAuthenticatesRegisteredClientAtTokenEndpoint() {
        given()
                .auth().preemptive().basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:test:unsupported-grant")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .body("error", equalTo(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE));
    }

    @Test
    void postCredentialsIssueIntrospectAndRevokeTokenAndStartDeviceAuthorization() {
        String token = given().contentType(ContentType.URLENC)
                .formParam("client_id", "post-client").formParam("client_secret", "client-secret")
                .formParam("grant_type", "client_credentials").formParam("scope", "message.read")
                .post("/oauth2/token").then().statusCode(200)
                .body("token_type", equalTo("Bearer")).extract().path("access_token");
        given().contentType(ContentType.URLENC)
                .formParam("client_id", "post-client").formParam("client_secret", "client-secret")
                .formParam("token", token).post("/oauth2/introspect").then().statusCode(200)
                .body("active", equalTo(true)).body("client_id", equalTo("post-client"));
        given().contentType(ContentType.URLENC)
                .formParam("client_id", "post-client").formParam("client_secret", "client-secret")
                .formParam("token", token).post("/oauth2/revoke").then().statusCode(200).body(equalTo(""));
        given().contentType(ContentType.URLENC)
                .formParam("client_id", "post-client").formParam("client_secret", "client-secret")
                .formParam("token", token).post("/oauth2/introspect").then().statusCode(200)
                .body("active", equalTo(false));
        given().contentType(ContentType.URLENC)
                .formParam("client_id", "post-client").formParam("client_secret", "client-secret")
                .formParam("scope", "message.read").post("/oauth2/device_authorization").then().statusCode(200)
                .body("device_code", notNullValue()).body("user_code", notNullValue());
    }

    @Test
    void rejectsWrongPostSecretUnknownClientAndUnregisteredAuthenticationMethodAtEveryClientEndpoint() {
        for (String endpoint : List.of("/oauth2/token", "/oauth2/introspect", "/oauth2/revoke",
                "/oauth2/device_authorization")) {
            for (String client : List.of("post-client", "unknown-client", "oauth-client", "public-client")) {
                given().contentType(ContentType.URLENC)
                        .formParam("client_id", client)
                        .formParam("client_secret", "post-client".equals(client) ? "wrong-secret" : "client-secret")
                        .post(endpoint).then().statusCode(401).body("error", equalTo("invalid_client"))
                        .body("error_description", nullValue());
            }
            given().auth().preemptive().basic("post-client", "client-secret")
                    .post(endpoint).then().statusCode(401).body("error", equalTo("invalid_client"));
        }
    }

    @Test
    void rejectsIncompleteBlankAndRepeatedPostCredentials() {
        for (String body : List.of(
                "client_secret=client-secret",
                "client_id=&client_secret=client-secret",
                "client_id=+&client_secret=client-secret",
                "client_id=post-client&client_secret=",
                "client_id=post-client&client_secret=+",
                "client_id=post-client&client_id=post-client&client_secret=client-secret",
                "client_id=post-client&client_secret=client-secret&client_secret=client-secret",
                "client_id=post-client&client_secret=&client_secret=client-secret")) {
            given().contentType(ContentType.URLENC).body(body).post("/oauth2/token").then()
                    .statusCode(400).header("WWW-Authenticate", nullValue())
                    .body("error", equalTo("invalid_request"));
        }
        given().contentType(ContentType.URLENC).formParam("client_id", "post-client")
                .post("/oauth2/token").then().statusCode(401).body("error", equalTo("invalid_client"));
    }

    @Test
    void doesNotReadPostCredentialsFromQueryStringOrJson() {
        given().contentType(ContentType.URLENC)
                .queryParam("client_id", "post-client").queryParam("client_secret", "client-secret")
                .formParam("grant_type", "client_credentials").post("/oauth2/token").then()
                .statusCode(401).body("error", equalTo("invalid_client"));
        given().contentType(ContentType.JSON)
                .body("""
                        {"client_id":"post-client","client_secret":"client-secret","grant_type":"client_credentials"}
                        """).post("/oauth2/token").then().statusCode(401).body("error", equalTo("invalid_client"));
    }

    @Test
    void rejectsMixedAuthenticationMethodsAndRepeatedAuthorizationHeaders() {
        for (String endpoint : List.of("/oauth2/token", "/oauth2/introspect", "/oauth2/revoke",
                "/oauth2/device_authorization")) {
            for (String credential : List.of("client_secret", "client_assertion", "client_assertion_type")) {
                given().auth().preemptive().basic("oauth-client", "client-secret").contentType(ContentType.URLENC)
                        .formParam("client_id", "post-client").formParam(credential, "client-secret")
                        .post(endpoint).then().statusCode(400).body("error", equalTo("invalid_request"));
            }
            for (String assertion : List.of("client_assertion", "client_assertion_type")) {
                given().contentType(ContentType.URLENC)
                        .formParam("client_id", "post-client").formParam("client_secret", "client-secret")
                        .formParam(assertion, "unsupported").post(endpoint).then()
                        .statusCode(400).body("error", equalTo("invalid_request"));
            }
            given().headers(new Headers(new Header("Authorization", "Basic b2F1dGgtY2xpZW50OmNsaWVudC1zZWNyZXQ="),
                    new Header("Authorization", "Bearer other")))
                    .post(endpoint).then().statusCode(400).body("error", equalTo("invalid_request"));
            given().header("Authorization", "Bearer unsupported").contentType(ContentType.URLENC)
                    .formParam("client_id", "post-client").formParam("client_secret", "client-secret")
                    .post(endpoint).then().statusCode(400).body("error", equalTo("invalid_request"));
        }
    }

    @Test
    void invalidClientSecretIsRejectedWithBasicChallenge() {
        given()
                .auth().preemptive().basic("oauth-client", "wrong-secret")
                .when().post("/oauth2/token")
                .then()
                .statusCode(401)
                .contentType(ContentType.JSON)
                .header("WWW-Authenticate", equalTo("Basic realm=\"oauth2/client\""))
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_CLIENT))
                .body("error_description", nullValue())
                .body("error_uri", nullValue());
    }

    @Test
    void applicationBasicAuthenticationStillOwnsNonTokenEndpoints() {
        given()
                .auth().preemptive().basic("application-user", "application-password")
                .when().get("/application")
                .then()
                .statusCode(200)
                .body(equalTo("application-user"));
    }

    @Test
    void applicationUserCannotAuthenticateAsOAuthClient() {
        given()
                .auth().preemptive().basic("application-user", "application-password")
                .when().post("/oauth2/token")
                .then()
                .statusCode(401)
                .contentType(ContentType.JSON)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    @Test
    void oauthClientCannotAuthenticateAtApplicationEndpoint() {
        given()
                .auth().preemptive().basic("oauth-client", "client-secret")
                .when().get("/application")
                .then()
                .statusCode(401);
    }

    @Test
    void malformedClientBasicCredentialsAreRejected() {
        given()
                .header("Authorization", "Basic not-base64")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .header("WWW-Authenticate", nullValue())
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST));
    }

    @Test
    void publicIdentificationCannotReplaceClientCredentialsEvenWhenGrantIsRegistered() {
        for (String grant : new String[] {
                "client_credentials",
                "password",
                "urn:ietf:params:oauth:grant-type:token-exchange"
        }) {
            given().contentType(ContentType.URLENC)
                    .formParam("client_id", "public-client")
                    .formParam("grant_type", grant)
                    .formParam("username", "application-user")
                    .formParam("password", "application-password")
                    .formParam("subject_token", "token")
                    .formParam(
                            "subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                    .post("/oauth2/token")
                    .then()
                    .statusCode(400)
                    .body("error", equalTo("invalid_client"));
        }
    }

    @Test
    void publicClientCannotAccessIntrospectionOrRevocationByForgingGrantParameters() {
        for (String endpoint : new String[] { "/oauth2/introspect", "/oauth2/revoke" }) {
            given().contentType(ContentType.URLENC)
                    .formParam("client_id", "public-client")
                    .formParam("grant_type", "authorization_code")
                    .formParam("code", "code")
                    .formParam("code_verifier", "a".repeat(43))
                    .formParam("token", "token")
                    .post(endpoint)
                    .then()
                    .statusCode(401)
                    .body("error", equalTo("invalid_client"));
        }
    }

    @Test
    void publicClientIdentificationDoesNotFallBackFromUnsupportedCredentials() {
        for (String credential : new String[] { "client_secret", "client_assertion" }) {
            given().contentType(ContentType.URLENC)
                    .formParam("client_id", "public-client")
                    .formParam("grant_type", "authorization_code")
                    .formParam("code", "code")
                    .formParam(credential, "unsupported")
                    .formParams("client_assertion".equals(credential)
                            ? java.util.Map.of("client_assertion_type",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                            : java.util.Map.of())
                    .post("/oauth2/token")
                    .then()
                    .statusCode(401)
                    .body("error", equalTo("invalid_client"));
        }
    }

    @Path("/application")
    public static class ApplicationEndpoint {

        @Inject
        SecurityIdentity securityIdentity;

        @GET
        @Authenticated
        @Produces(MediaType.TEXT_PLAIN)
        public String application() {
            return securityIdentity.getPrincipal().getName();
        }
    }

    @Singleton
    public static class ApplicationIdentityProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {

        @Override
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            if (!"application-user".equals(request.getUsername())) {
                return Uni.createFrom().nullItem();
            }
            PasswordCredential passwordCredential = request.getPassword();
            if (!Arrays.equals("application-password".toCharArray(), passwordCredential.getPassword())) {
                return Uni.createFrom().failure(new AuthenticationFailedException());
            }
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                    .addRole("application-user")
                    .build());
        }
    }
}
