package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.grant.password.PasswordGrant;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordGrantRequestParser;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
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
import io.quarkus.test.InMemoryLogHandler;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.restassured.config.HttpClientConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class OAuth2PasswordGrantTest {

    private static final String OAUTH_CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";
    private static final String TOKEN_CLIENT_SECRET_HASH = "$2y$10$ZgQdJ3httrP2QQBD/6Tyle6WTzcrBmVR7R8Rw4n966J8sctedV4va";
    private static final String REFRESH_CLIENT_SECRET_HASH = "$2a$10$XGwB4UKiactHgawjTMaioe5al6.c1N0AMz3PE4xi.cAZ/f.9OV1yK";
    private static final String OPENID_CLIENT_SECRET_HASH = "$2a$10$zbxRJXxAAXD/gLh4SXKGouLCzyn6MmoFVVJUtsYcR9qDlSY/QDplO";
    private static final String SYNC_SQL_FAILURE = "Synchronous identity lookup failed: jdbc:postgresql://private-db/accounts";
    private static final String ASYNC_SQL_FAILURE = "Asynchronous identity lookup failed: db-password=internal-secret";
    private static final String EXPLICIT_SQL_FAILURE = "Classified identity lookup failed: account-table=private_users";
    private static final String CUSTOM_SYNC_SQL_FAILURE = "Synchronous custom grant failed: db-password=custom-secret";
    private static final String CUSTOM_ASYNC_SQL_FAILURE = "Asynchronous custom grant failed: account-table=custom_users";

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
        TestGrantHandler.lastIssuedToken = null;
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
    void synchronousIdentityProviderFailureReturnsServerError() {
        assertServerError(passwordRequest("oauth-client", "identity-sync-failure", "resource-owner-password"),
                SYNC_SQL_FAILURE);
        assertEquals(1, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void asynchronousIdentityProviderFailureReturnsServerError() {
        assertServerError(passwordRequest("oauth-client", "identity-async-failure", "resource-owner-password"),
                ASYNC_SQL_FAILURE);
        assertEquals(1, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void classifiedIdentityProviderServerErrorDoesNotExposeDetails() {
        assertServerError(passwordRequest("oauth-client", "identity-server-error", "resource-owner-password"),
                EXPLICIT_SQL_FAILURE);
        assertEquals(1, ResourceOwnerIdentityProvider.invocations.get());
    }

    @ParameterizedTest
    @ValueSource(strings = { "identity-sync-protocol-error", "identity-async-protocol-error" })
    void preservesIdentityProviderProtocolError(String username) {
        passwordRequest("oauth-client", username, "resource-owner-password")
                .post("/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo(OAuth2ErrorCodes.INVALID_REQUEST))
                .body("error_description", equalTo("Resource-owner policy rejected the request"))
                .body("error_uri", equalTo("https://issuer.example.com/policy"));
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
                .statusCode(500)
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
                .statusCode(500)
                .body("error", equalTo(OAuth2ErrorCodes.SERVER_ERROR));
    }

    @ParameterizedTest
    @ValueSource(strings = { "sync-failure", "async-failure" })
    void customGrantFailureReturnsServerError(String failureMode) {
        assertServerError(given().auth()
                .preemptive()
                .basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:test:grant")
                .formParam("custom_value", failureMode),
                "sync-failure".equals(failureMode) ? CUSTOM_SYNC_SQL_FAILURE : CUSTOM_ASYNC_SQL_FAILURE);
        assertEquals(1, TestGrantHandler.invocations.get());
        assertEquals(0, ResourceOwnerIdentityProvider.invocations.get());
    }

    @Test
    void tokenResponseSerializationFailureReturnsServerError() {
        assertServerError(given()
                .config(RestAssuredConfig.config().httpClient(
                        HttpClientConfig.httpClientConfig().setParam("http.socket.timeout", 5000)))
                .auth().preemptive().basic("oauth-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "urn:test:grant")
                .formParam("custom_value", "serialization-failure"),
                failure -> failure instanceof InvalidDefinitionException
                        && failure.getMessage().contains("custom_value"));
        assertEquals(1, TestGrantHandler.invocations.get());
        assertNotNull(TestGrantHandler.lastIssuedToken);
        assertNotNull(authorizations.findByToken(TestGrantHandler.lastIssuedToken, OAuth2TokenType.ACCESS_TOKEN));
    }

    private static void assertServerError(io.restassured.specification.RequestSpecification request,
            String sqlFailureMessage) {
        assertServerError(request,
                failure -> failure instanceof SQLException && sqlFailureMessage.equals(failure.getMessage()));
    }

    private static void assertServerError(io.restassured.specification.RequestSpecification request,
            Predicate<Throwable> expectedCause) {
        var logger = Logger.getLogger(OAuth2ErrorAuthenticationFailureHandler.class.getName());
        var logHandler = new InMemoryLogHandler(record -> true);
        logger.addHandler(logHandler);
        try {
            request.post("/oauth2/token")
                    .then()
                    .statusCode(500)
                    .contentType(ContentType.JSON)
                    .body("$", equalTo(Map.of("error", OAuth2ErrorCodes.SERVER_ERROR)));
            assertTrue(logHandler.getRecords().stream().anyMatch(record -> retainsFailure(record, expectedCause)),
                    "Server failures must be logged at ERROR with the original cause");
        } finally {
            logger.removeHandler(logHandler);
            logHandler.close();
        }
    }

    private static boolean retainsFailure(LogRecord record, Predicate<Throwable> expectedCause) {
        if (record.getLevel().intValue() < Level.SEVERE.intValue()) {
            return false;
        }
        for (Throwable failure = record.getThrown(); failure != null; failure = failure.getCause()) {
            if (expectedCause.test(failure)) {
                return true;
            }
        }
        return false;
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
        return passwordRequest(clientId, "resource-owner", password);
    }

    private static io.restassured.specification.RequestSpecification passwordRequest(
            String clientId, String username, String password) {
        return given().auth()
                .preemptive()
                .basic(clientId, "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("username", username)
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
            switch (request.getUsername()) {
                case "identity-sync-failure":
                    throw new RuntimeException("Identity lookup failed", new SQLException(SYNC_SQL_FAILURE));
                case "identity-async-failure":
                    return Uni.createFrom().failure(new SQLException(ASYNC_SQL_FAILURE));
                case "identity-server-error":
                    return Uni.createFrom().failure(new OAuth2AuthenticationException(
                            new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                                    "Identity storage unavailable: db-password=internal-secret",
                                    "https://private-db.example.com/debug"),
                            new SQLException(EXPLICIT_SQL_FAILURE)));
                case "identity-sync-protocol-error":
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                            "Resource-owner policy rejected the request", "https://issuer.example.com/policy"));
                case "identity-async-protocol-error":
                    return Uni.createFrom().failure(new OAuth2AuthenticationException(
                            new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                                    "Resource-owner policy rejected the request", "https://issuer.example.com/policy")));
                default:
                    break;
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
        static volatile String lastIssuedToken;
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
            invocations.incrementAndGet();
            if ("sync-failure".equals(context.request().getFormAttribute("custom_value"))) {
                throw new RuntimeException("Custom grant failed", new SQLException(CUSTOM_SYNC_SQL_FAILURE));
            }
            return Uni.createFrom()
                    .deferred(
                            () -> {
                                var user = (QuarkusHttpUser) context.user();
                                var request = new TestGrantRequest(
                                        context.request().getFormAttribute("custom_value"),
                                        user.getSecurityIdentity());
                                if ("null-result".equals(request.value())) {
                                    return Uni.createFrom().nullItem();
                                }
                                if ("async-failure".equals(request.value())) {
                                    return Uni.createFrom().failure(new SQLException(CUSTOM_ASYNC_SQL_FAILURE));
                                }
                                if (!"accepted".equals(request.value()) && !"serialization-failure".equals(request.value())) {
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
                                            lastIssuedToken = token.getTokenValue();
                                            return new TokenIssuanceResult(
                                                    client,
                                                    request.client(),
                                                    token,
                                                    null,
                                                    Map.of("custom_value", "serialization-failure".equals(request.value())
                                                            ? new Object()
                                                            : request.value()));
                                        });
                            });
        }
    }
}
