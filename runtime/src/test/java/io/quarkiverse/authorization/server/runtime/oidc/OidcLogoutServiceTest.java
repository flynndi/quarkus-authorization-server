package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.h2.jdbcx.JdbcConnectionPool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutRequest;
import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutValidator;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTestSupport;
import io.quarkiverse.authorization.server.runtime.oidc.logout.OidcLogoutService;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OidcLogoutServiceTest {
    private static final String REDIRECT = "https://client.example/bye?existing=1";
    private JdbcConnectionPool dataSource;
    private JdbcRegisteredClientRepository clients;
    private JdbcOAuth2AuthorizationService service;
    private OidcLogoutService provider;
    private RegisteredClient client;

    @BeforeEach
    void setup() {
        this.dataSource = JdbcConnectionPool.create(
                "jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        this.clients = new JdbcRegisteredClientRepository(this.dataSource);
        this.client = RegisteredClient.withId("registration")
                .clientId("client")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("openid")
                .postLogoutRedirectUri(REDIRECT)
                .build();
        this.clients.save(this.client);
        this.service = new JdbcOAuth2AuthorizationService(this.dataSource, this.clients);
        this.provider = new OidcLogoutService(this.clients, this.service, new OidcLogoutValidator());
        save(Instant.now().minusSeconds(60), Instant.now().plusSeconds(60), false, Map.of());
    }

    @AfterEach
    void close() {
        this.dataSource.dispose();
    }

    @Test
    void bindsPersistedHintClientAndSessionWithoutRevokingTokens() {
        var request = request("hint", identity("alice"), "session", "client", REDIRECT);
        var result = this.provider.validate(request);
        assertSame(request.getPrincipal(), result.principal());
        assertEquals(REDIRECT, result.postLogoutRedirectUri());
        assertEquals("state", result.state());
        assertTrue(this.service.findById("authorization").getAccessToken().isActive());
    }

    @Test
    void acceptsExpiredHintAndNoSession() {
        save(Instant.now().minusSeconds(3600), Instant.now().minusSeconds(60), false, Map.of());
        assertEquals(
                REDIRECT,
                this.provider
                        .validate(request("hint", identity(null), null, null, REDIRECT))
                        .postLogoutRedirectUri());
    }

    @Test
    void rejectsUnknownWrongTypeInvalidatedAndBeforeUse() {
        assertError("invalid_token", request("missing", identity(null), null, null, REDIRECT));
        assertError("invalid_token", request("access", identity(null), null, null, REDIRECT));
        save(Instant.now().minusSeconds(60), Instant.now().plusSeconds(60), true, Map.of());
        assertError("invalid_token", request("hint", identity(null), null, null, REDIRECT));
        save(
                Instant.now(),
                Instant.now().plusSeconds(60),
                false,
                Map.of("nbf", Instant.now().plusSeconds(30)));
        assertError("invalid_token", request("hint", identity(null), null, null, REDIRECT));
    }

    @Test
    void rejectsClientAudienceRedirectUserAndSessionConfusion() {
        assertError("invalid_request", request("hint", identity(null), null, "other", REDIRECT));
        for (String uri : List.of(
                "https://evil.example/bye",
                REDIRECT + "&injected=1",
                "https://client.example/bye")) {
            assertError("invalid_request", request("hint", identity(null), null, "client", uri));
        }
        assertError(
                "invalid_token", request("hint", identity("bob"), "session", "client", REDIRECT));
        assertError(
                "invalid_token",
                request("hint", identity("alice"), "other-session", "client", REDIRECT));
        save(Instant.now(), Instant.now().plusSeconds(60), false, Map.of("aud", List.of("other")));
        assertError("invalid_token", request("hint", identity(null), null, null, REDIRECT));
    }

    @Test
    void persistsSnapshotAndClientPostLogoutUrisAcrossNewRepositoryInstances() {
        SessionInformation expected = new SessionInformation(
                "alice", "public-session-id", Instant.now().minusSeconds(90));
        var authorization = this.service.findById("authorization");
        this.service.save(
                OAuth2Authorization.from(authorization)
                        .attribute(SessionInformation.class.getName(), expected)
                        .build());
        JdbcRegisteredClientRepository restoredClients = new JdbcRegisteredClientRepository(this.dataSource);
        JdbcOAuth2AuthorizationService restoredService = new JdbcOAuth2AuthorizationService(this.dataSource, restoredClients);
        assertEquals(
                expected,
                restoredService
                        .findById("authorization")
                        .getAttribute(SessionInformation.class.getName()));
        assertEquals(
                Set.of(REDIRECT),
                restoredClients.findById("registration").getPostLogoutRedirectUris());
        var updated = RegisteredClient.from(this.client)
                .postLogoutRedirectUris(Set::clear)
                .postLogoutRedirectUri("https://client.example/new")
                .build();
        this.clients.save(updated);
        assertEquals(
                updated.getPostLogoutRedirectUris(),
                restoredClients.findById("registration").getPostLogoutRedirectUris());
        assertThrows(
                UnsupportedOperationException.class,
                () -> updated.getPostLogoutRedirectUris().clear());
        assertThrows(
                IllegalArgumentException.class,
                () -> RegisteredClient.from(this.client)
                        .postLogoutRedirectUri("https://client.example/#fragment")
                        .build());
    }

    private void save(
            Instant issuedAt,
            Instant expiresAt,
            boolean invalidated,
            Map<String, Object> overrides) {
        Map<String, Object> claims = new LinkedHashMap<>(
                Map.of(
                        "sub",
                        "custom-subject",
                        "aud",
                        List.of("client"),
                        "sid",
                        "session"));
        claims.putAll(overrides);
        OidcIdToken idToken = new OidcIdToken("hint", issuedAt, expiresAt, claims);
        this.service.save(
                OAuth2Authorization.withRegisteredClient(this.client)
                        .id("authorization")
                        .principalName("alice")
                        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                        .authorizedScopes(Set.of("openid"))
                        .accessToken(
                                new OAuth2AccessToken(
                                        OAuth2AccessToken.TokenType.BEARER,
                                        "access",
                                        Instant.now(),
                                        Instant.now().plusSeconds(300),
                                        Set.of("openid")))
                        .token(
                                idToken,
                                metadata -> {
                                    metadata.put(
                                            OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
                                    metadata.put(
                                            OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                            invalidated);
                                })
                        .build());
    }

    private static SecurityIdentity identity(String name) {
        return name == null
                ? QuarkusSecurityIdentity.builder().setAnonymous(true).build()
                : QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal(name))
                        .build();
    }

    private static OidcLogoutRequest request(
            String hint,
            SecurityIdentity principal,
            String session,
            String client,
            String redirect) {
        return new OidcLogoutRequest(hint, principal, session, client, redirect, "state");
    }

    private void assertError(String code, OidcLogoutRequest request) {
        var exception = assertThrows(
                OAuth2AuthenticationException.class, () -> this.provider.validate(request));
        assertEquals(code, exception.getError().getErrorCode());
    }
}
