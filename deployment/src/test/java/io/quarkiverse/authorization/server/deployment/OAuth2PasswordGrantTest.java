package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.grant.password.PasswordGrant;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordGrantRequestParser;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class OAuth2PasswordGrantTest {

    private static final String OAUTH_CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";
    private static final String TOKEN_CLIENT_SECRET_HASH = "$2y$10$ZgQdJ3httrP2QQBD/6Tyle6WTzcrBmVR7R8Rw4n966J8sctedV4va";
    private static final String REFRESH_CLIENT_SECRET_HASH = "$2a$10$XGwB4UKiactHgawjTMaioe5al6.c1N0AMz3PE4xi.cAZ/f.9OV1yK";
    private static final String OPENID_CLIENT_SECRET_HASH = "$2a$10$zbxRJXxAAXD/gLh4SXKGouLCzyn6MmoFVVJUtsYcR9qDlSY/QDplO";

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClass(ResourceOwnerIdentityProvider.class)
                            .addClasses(
                                    TestGrantHandler.class, TestGrantRequest.class)
                            .addAsResource("privateKey.pem")
                            .addAsResource("publicKey.pem")
                            .addAsResource(
                                    new StringAsset(
                                            """
                                                    quarkus.http.auth.basic=true
                                                    quarkus.authorization-server.issuer=https://issuer.example.com
                                                    quarkus.authorization-server.signing.key-id=test-key
                                                    quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                                    quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                                    quarkus.authorization-server.clients.oauth-client.client-secret=%s
                                                    quarkus.authorization-server.clients.oauth-client.authorization-grant-types=password,urn:test:grant
                                                    quarkus.authorization-server.clients.oauth-client.scopes=message.read,message.write
                                                    quarkus.authorization-server.clients.token-client.client-secret=%s
                                                    quarkus.authorization-server.clients.token-client.authorization-grant-types=password,refresh_token
                                                    quarkus.authorization-server.clients.token-client.scopes=message.read
                                                    quarkus.authorization-server.clients.refresh-client.client-secret=%s
                                                    quarkus.authorization-server.clients.refresh-client.authorization-grant-types=refresh_token
                                                    quarkus.authorization-server.clients.refresh-client.scopes=message.read
                                                    quarkus.authorization-server.clients.openid-client.client-secret=%s
                                                    quarkus.authorization-server.clients.openid-client.authorization-grant-types=password
                                                    quarkus.authorization-server.clients.openid-client.scopes=openid,message.read
                                                    """
                                                    .formatted(
                                                            OAUTH_CLIENT_SECRET_HASH,
                                                            TOKEN_CLIENT_SECRET_HASH,
                                                            REFRESH_CLIENT_SECRET_HASH,
                                                            OPENID_CLIENT_SECRET_HASH)),
                                    "application.properties"));

    @Inject
    Instance<PasswordGrantRequestParser> converter;

    @Inject
    Instance<PasswordGrant> provider;

    @Inject
    Instance<PasswordGrantHandler> passwordGrantHandler;

    @BeforeEach
    void resetResourceOwnerAuthentication() {
        ResourceOwnerIdentityProvider.invocations.set(0);
        ResourceOwnerIdentityProvider.clientPrincipalName = null;
        TestGrantHandler.invocations.set(0);
    }

    @Test
    void passwordGrantBeansAreInstalledWithTheExtension() {
        assertTrue(
                this.converter.isUnsatisfied(),
                "The HTTP parser is internal, not an application bean");
        assertTrue(this.provider.isResolvable());
        assertTrue(this.passwordGrantHandler.isResolvable());
    }

    @Test
    void authenticatesResourceOwnerAndReturnsAccessToken() {
        validPasswordRequest()
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .header("Cache-Control", equalTo("no-store"))
                .header("Pragma", equalTo("no-cache"))
                .body("access_token", notNullValue())
                .body("token_type", equalTo("Bearer"))
                .body("expires_in", equalTo(300))
                .body(
                        "scope",
                        anyOf(
                                equalTo("message.read message.write"),
                                equalTo("message.write message.read")))
                .body("refresh_token", nullValue())
                .body("id_token", nullValue());

        assertEquals(1, ResourceOwnerIdentityProvider.invocations.get());
        assertEquals("oauth-client", ResourceOwnerIdentityProvider.clientPrincipalName);
    }

    @Test
    void issuesRefreshTokenOnlyWhenClientDeclaresRefreshTokenGrant() {
        String refreshToken = tokenClientPasswordRequest()
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", notNullValue())
                .extract()
                .path("refresh_token");

        given().auth()
                .preemptive()
                .basic("token-client", "token-client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("access_token", notNullValue())
                .body("refresh_token", equalTo(refreshToken));
    }

    @Test
    void acceptsExplicitRegisteredScopeSubset() {
        validPasswordRequest()
                .formParam("scope", "message.read")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("scope", equalTo("message.read"));

        assertEquals(1, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void rejectsInvalidResourceOwnerCredentials() {
        passwordRequest("oauth-client", "wrong-password")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .contentType(ContentType.JSON)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_GRANT))
                .body("error_description", nullValue());

        assertEquals(1, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void rejectsMissingUsernameBeforeResourceOwnerAuthentication() {
        given().auth()
                .preemptive()
                .basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("password", "resource-owner-password")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: username"));

        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void rejectsRepeatedPasswordBeforeResourceOwnerAuthentication() {
        given().auth()
                .preemptive()
                .basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password", "another-password")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: password"));

        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void rejectsBlankAndRepeatedScopeBeforeResourceOwnerAuthentication() {
        validPasswordRequest()
                .formParam("scope", " ")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: scope"));
        validPasswordRequest()
                .formParam("scope", "message.read", "message.write")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: scope"));

        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void rejectsClientWithoutPasswordGrant() {
        passwordRequest("refresh-client")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));

        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void rejectsScopeOutsideRegisteredScopes() {
        validPasswordRequest()
                .formParam("scope", "messages.admin")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_SCOPE));

        assertEquals(1, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void issuesIdTokenFromExplicitOrOmittedScopesWithoutOidcEndpoints() {
        given().get("/.well-known/openid-configuration").then().statusCode(404);
        for (String scope : List.of("openid", "")) {
            var request = passwordRequest("openid-client");
            if (!scope.isEmpty()) {
                request.formParam("scope", scope);
            }
            request.when()
                    .post("/oauth2/token")
                    .then()
                    .statusCode(200)
                    .body("access_token", notNullValue())
                    .body("id_token", notNullValue())
                    .body("refresh_token", nullValue())
                    .body(
                            "scope",
                            scope.isEmpty()
                                    ? anyOf(
                                            equalTo("openid message.read"),
                                            equalTo("message.read openid"))
                                    : equalTo("openid"));
        }

        assertEquals(2, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void delegatesRefreshTokenGrantWithoutResourceOwnerAuthentication() {
        given().auth()
                .preemptive()
                .basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("OAuth 2.0 Parameter: refresh_token"));

        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void delegatesAdditionalGrantWithoutChangingTokenEndpointHandler() {
        given().auth()
                .preemptive()
                .basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:test:grant")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.SERVER_ERROR));

        assertEquals(1, TestGrantHandler.invocations.get());
        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void rejectsMissingClientAuthenticationWithBasicChallenge() {
        given().contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password")
                .when()
                .post("/oauth2/token")
                .then()
                .statusCode(401)
                .contentType(ContentType.JSON)
                .header("WWW-Authenticate", equalTo("Basic realm=\"oauth2/client\""))
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_CLIENT));

        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Inject
    OAuth2AuthorizationService authorizations;

    @Test
    void customGrantUsesItsOwnRequestAndReturnsTheSharedTokenResult() {
        String token = given().auth()
                .preemptive()
                .basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:test:grant")
                .formParam("custom_value", "accepted")
                .post("/oauth2/token")
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"))
                .body("custom_value", equalTo("accepted"))
                .extract()
                .path("access_token");
        assertNotNull(authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN));
        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void nullCustomGrantResultIsAnOAuthServerError() {
        given().auth()
                .preemptive()
                .basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:test:grant")
                .formParam("custom_value", "null-result")
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.SERVER_ERROR));
    }

    private static io.restassured.specification.RequestSpecification validPasswordRequest() {
        return passwordRequest("oauth-client");
    }

    private static io.restassured.specification.RequestSpecification tokenClientPasswordRequest() {
        return given().auth()
                .preemptive()
                .basic("token-client", "token-client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", "resource-owner-password");
    }

    private static io.restassured.specification.RequestSpecification passwordRequest(
            String clientId) {
        return passwordRequest(clientId, "resource-owner-password");
    }

    private static io.restassured.specification.RequestSpecification passwordRequest(
            String clientId, String password) {
        return given().auth()
                .preemptive()
                .basic(clientId, "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", "resource-owner")
                .formParam("password", password);
    }

    @Singleton
    public static class ResourceOwnerIdentityProvider
            implements IdentityProvider<UsernamePasswordAuthenticationRequest> {

        static final AtomicInteger invocations = new AtomicInteger();
        static volatile String clientPrincipalName;

        @Override
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(
                UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            invocations.incrementAndGet();
            RoutingContext routingContext = HttpSecurityUtils.getRoutingContextAttribute(request);
            if (routingContext != null && routingContext.user() instanceof QuarkusHttpUser user) {
                clientPrincipalName = user.getSecurityIdentity().getPrincipal().getName();
            }
            if (!"resource-owner".equals(request.getUsername())
                    || !Arrays.equals(
                            "resource-owner-password".toCharArray(),
                            request.getPassword().getPassword())) {
                return Uni.createFrom().failure(new AuthenticationFailedException());
            }
            return Uni.createFrom()
                    .item(
                            QuarkusSecurityIdentity.builder()
                                    .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                                    .addRole("resource-owner")
                                    .build());
        }
    }

    public record TestGrantRequest(String value, SecurityIdentity client) {
    }

    @Singleton
    public static class TestGrantHandler implements TokenGrantHandler {
        private static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType("urn:test:grant");
        static final AtomicInteger invocations = new AtomicInteger();
        @Inject
        ProtocolExecutor executor;
        @Inject
        OAuth2AuthorizationService authorizations;

        @Override
        public AuthorizationGrantType getGrantType() {
            return GRANT_TYPE;
        }

        @Override
        public Uni<TokenIssuanceResult> handle(RoutingContext context) {
            return Uni.createFrom()
                    .deferred(
                            () -> {
                                invocations.incrementAndGet();
                                var user = (QuarkusHttpUser) context.user();
                                var request = new TestGrantRequest(
                                        context.request().getFormAttribute("custom_value"),
                                        user.getSecurityIdentity());
                                if ("null-result".equals(request.value())) {
                                    return Uni.createFrom().nullItem();
                                }
                                if (!"accepted".equals(request.value())) {
                                    return Uni.createFrom()
                                            .failure(
                                                    new OAuth2AuthenticationException(
                                                            OAuth2ErrorCodes.SERVER_ERROR));
                                }
                                return executor.execute(
                                        context,
                                        () -> {
                                            RegisteredClient client = request.client()
                                                    .getAttribute(
                                                            OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE);
                                            if (!client.getAuthorizationGrantTypes()
                                                    .contains(GRANT_TYPE)) {
                                                throw new OAuth2AuthenticationException(
                                                        OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
                                            }
                                            Instant now = Instant.now();
                                            var token = new OAuth2AccessToken(
                                                    OAuth2AccessToken.TokenType.BEARER,
                                                    java.util.UUID.randomUUID().toString(),
                                                    now,
                                                    now.plusSeconds(60));
                                            authorizations.save(
                                                    OAuth2Authorization.withRegisteredClient(client)
                                                            .principalName(
                                                                    request.client()
                                                                            .getPrincipal()
                                                                            .getName())
                                                            .authorizationGrantType(GRANT_TYPE)
                                                            .token(
                                                                    token,
                                                                    metadata -> metadata.put(
                                                                            OAuth2TokenFormat.class
                                                                                    .getName(),
                                                                            OAuth2TokenFormat.REFERENCE
                                                                                    .getValue()))
                                                            .build());
                                            return new TokenIssuanceResult(
                                                    client,
                                                    request.client(),
                                                    token,
                                                    null,
                                                    Map.of("custom_value", request.value()));
                                        });
                            });
        }
    }
}
