package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.ClientCredentialsGrant;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.web.ClientCredentialsGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.web.ClientCredentialsRequestParser;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;

class OAuth2ClientCredentialsGrantTest {

    private static final String CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";
    private static final String TOKEN_PATH = "/machine/token";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.http.root-path=/api
                                                    quarkus.authorization-server.issuer=https://issuer.example/api
                                                    quarkus.authorization-server.token-endpoint=/machine/token
                                                    quarkus.authorization-server.oidc.enabled=true
                                                    quarkus.authorization-server.signing.key-id=test-key
                                                    quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                                    quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.clients.machine.client-secret=%s
                                                    quarkus.authorization-server.clients.machine.authorization-grant-types=client_credentials,refresh_token
                                                    quarkus.authorization-server.clients.machine.scopes=message.read,openid
                                                    quarkus.authorization-server.clients.machine.access-token-time-to-live=PT2M
                                                    quarkus.authorization-server.clients.legacy.client-secret=%s
                                                    quarkus.authorization-server.clients.legacy.authorization-grant-types=password
                                                    quarkus.authorization-server.clients.public-client.client-authentication-methods=none
                                                    quarkus.authorization-server.clients.public-client.authorization-grant-types=authorization_code,client_credentials
                                                    quarkus.authorization-server.clients.public-client.redirect-uris=https://rp.example/callback
                                                    """
                                                    .formatted(
                                                            CLIENT_SECRET_HASH,
                                                            BcryptUtil.bcryptHash(
                                                                    "legacy-secret"))),
                                    "application.properties"));

    @Inject
    Instance<ClientCredentialsRequestParser> converter;
    @Inject
    Instance<ClientCredentialsGrant> provider;
    @Inject
    Instance<ClientCredentialsGrantHandler> handler;
    @Inject
    Instance<TokenGrantHandler> handlers;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    OAuth2AuthorizationService authorizations;

    @Test
    void installsClientCredentialsAlongsideExistingGrantHandlers() {
        assertTrue(
                this.converter.isUnsatisfied(),
                "The HTTP parser is internal, not an application bean");
        assertTrue(this.provider.isResolvable());
        assertTrue(this.handler.isResolvable());
        assertEquals(Set.of(AuthorizationGrantType.PASSWORD, AuthorizationGrantType.AUTHORIZATION_CODE,
                AuthorizationGrantType.REFRESH_TOKEN, AuthorizationGrantType.CLIENT_CREDENTIALS,
                AuthorizationGrantType.DEVICE_CODE, AuthorizationGrantType.TOKEN_EXCHANGE),
                this.handlers.stream().map(TokenGrantHandler::getGrantType)
                        .collect(java.util.stream.Collectors.toSet()));
        assertTrue(this.clients.findByClientId("machine").getRedirectUris().isEmpty());
    }

    @Test
    void signsAndStoresClientAccessTokenWithoutUserLoginOrConsent() {
        String token = tokenRequest().formParam("scope", "message.read openid").post(TOKEN_PATH)
                .then().statusCode(200).contentType(ContentType.JSON)
                .header("Cache-Control", equalTo("no-store")).header("Pragma", equalTo("no-cache"))
                .body("token_type", equalTo("Bearer")).body("expires_in", equalTo(120))
                .body("access_token", notNullValue()).body("$", not(hasKey("refresh_token")))
                .body("$", not(hasKey("id_token"))).extract().path("access_token");

        var saved = this.authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(saved);
        assertEquals("machine", saved.getPrincipalName());
        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, saved.getAuthorizationGrantType());
        assertEquals(Set.of("message.read", "openid"), saved.getAuthorizedScopes());
        assertEquals(saved.getAuthorizedScopes(), saved.getAccessToken().getToken().getScopes());
        assertEquals("machine", saved.getAccessToken().getClaims().get("sub"));
        assertTrue(saved.getAccessToken().isActive());
        assertTrue(saved.getAttributes().isEmpty());
        assertNull(saved.getRefreshToken());
        assertNull(saved.getToken(OidcIdToken.class));
    }

    @Test
    void omittedScopeDoesNotDefaultToRegisteredScopes() {
        String token = tokenRequest().post(TOKEN_PATH).then().statusCode(200)
                .body("$", not(hasKey("scope"))).extract().path("access_token");

        var saved = this.authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        assertTrue(saved.getAuthorizedScopes().isEmpty());
        assertTrue(saved.getAccessToken().getToken().getScopes().isEmpty());
        assertNull(saved.getAccessToken().getClaims().get("scope"));
    }

    @Test
    void rejectsUnregisteredScopesAndUnauthorizedGrant() {
        tokenRequest().formParam("scope", "message.admin").post(TOKEN_PATH).then().statusCode(400)
                .body("error", equalTo("invalid_scope"));
        tokenRequest().auth().preemptive().basic("legacy", "legacy-secret").post(TOKEN_PATH)
                .then().statusCode(400).body("error", equalTo("unauthorized_client"));
    }

    @Test
    void requiresValidClientCredentialsAndDoesNotAcceptPublicClientPkceAsASubstitute() {
        for (String client : new String[] { "machine", "unknown", "public-client" }) {
            tokenRequest().auth().preemptive().basic(client, "wrong-secret").post(TOKEN_PATH)
                    .then().statusCode(401).contentType(ContentType.JSON)
                    .header("WWW-Authenticate", equalTo("Basic realm=\"oauth2/client\""))
                    .body("error", equalTo("invalid_client"));
        }
        given().contentType(ContentType.URLENC).formParam("grant_type", "client_credentials")
                .post(TOKEN_PATH).then().statusCode(401).body("error", equalTo("invalid_client"));
        for (String client : new String[] { "machine", "public-client" }) {
            given().contentType(ContentType.URLENC)
                    .formParam("grant_type", "client_credentials")
                    .formParam("client_id", client)
                    .formParam("code", "not-an-authorization-code")
                    .formParam("code_verifier", "a".repeat(43))
                    .post(TOKEN_PATH)
                    // A known NONE client is identified, then rejected by the grant.
                    .then()
                    .statusCode("public-client".equals(client) ? 400 : 401)
                    .body("error", equalTo("invalid_client"));
        }
    }

    @Test
    void sharesTokenEndpointParameterValidation() {
        tokenRequest().formParam("grant_type", "authorization_code").post(TOKEN_PATH)
                .then().statusCode(400).body("error", equalTo("invalid_request"));
        tokenRequest().formParam("scope", "message.read", "openid").post(TOKEN_PATH)
                .then().statusCode(400).body("error", equalTo("invalid_request"));
    }

    @Test
    void customPathRootPathAndDiscoveryAgreeWithoutAddingFutureGrants() {
        for (String discovery : new String[] {
                "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"
        }) {
            given().get(discovery)
                    .then()
                    .statusCode(200)
                    .body("token_endpoint", equalTo("https://issuer.example/api/machine/token"))
                    .body(
                            "grant_types_supported",
                            containsInAnyOrder(
                                    "password",
                                    "authorization_code",
                                    "refresh_token",
                                    "client_credentials",
                                    AuthorizationGrantType.DEVICE_CODE.getValue(),
                                    AuthorizationGrantType.TOKEN_EXCHANGE.getValue()))
                    .body("response_types_supported", contains("code"))
                    .body(
                            "introspection_endpoint",
                            equalTo("https://issuer.example/api/oauth2/introspect"))
                    .body(
                            "introspection_endpoint_auth_methods_supported",
                            contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                    .body(
                            "revocation_endpoint",
                            equalTo("https://issuer.example/api/oauth2/revoke"))
                    .body(
                            "revocation_endpoint_auth_methods_supported",
                            contains("client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt"))
                    .body(
                            "device_authorization_endpoint",
                            equalTo("https://issuer.example/api/oauth2/device_authorization"));
        }
        tokenRequest().post("/oauth2/token").then().statusCode(404);
        given().get(TOKEN_PATH).then().statusCode(404);
        given().auth()
                .preemptive()
                .basic("machine", "client-secret")
                .contentType(ContentType.JSON)
                .body("{\"grant_type\":\"client_credentials\"}")
                .post(TOKEN_PATH)
                .then()
                .statusCode(415);
    }

    private static RequestSpecification tokenRequest() {
        return given().auth()
                .preemptive()
                .basic("machine", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "client_credentials");
    }
}
