package io.quarkiverse.authorization.server.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.h2.jdbcx.JdbcConnectionPool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.ClientCredentialsGrant;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTestSupport;
import io.quarkiverse.authorization.server.runtime.revocation.authentication.OAuth2TokenRevocationAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.revocation.authentication.OAuth2TokenRevocationAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.token.OAuth2AccessTokenGenerator;
import io.quarkiverse.authorization.server.runtime.token.OAuth2RefreshTokenGenerator;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class JdbcOAuth2AuthorizationServiceTest {

    private RegisteredClient registeredClient;
    private JdbcOAuth2AuthorizationService authorizationService;
    private JdbcConnectionPool dataSource;

    @BeforeEach
    void setUp() {
        this.dataSource = JdbcConnectionPool.create(
                "jdbc:h2:mem:"
                        + UUID.randomUUID()
                        + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
                "sa",
                "");
        this.dataSource.setMaxConnections(1);
        this.dataSource.setLoginTimeout(1);
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(this.dataSource);
        this.registeredClient = RegisteredClient.withId("client-registration")
                .clientId("messaging-client")
                .clientIdIssuedAt(Instant.parse("2026-08-31T01:00:00Z"))
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .build();
        registeredClientRepository.save(this.registeredClient);
        this.authorizationService = new JdbcOAuth2AuthorizationService(this.dataSource, registeredClientRepository);
    }

    @AfterEach
    void disposeDataSource() {
        this.dataSource.dispose();
    }

    @Test
    void persistsQueriesAndReplacesIdTokenWithClaimsAndTimestamps() {
        Instant issuedAt = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
                .issuer("https://issuer.example")
                .subject("resource-owner")
                .audience(List.of("messaging-client"))
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(1800))
                .nonce("nonce")
                .authTime(issuedAt.minusSeconds(60))
                .authenticationMethods(List.of("pwd", "mfa", "otp"))
                .build();
        OAuth2Authorization original = OAuth2Authorization.from(authorization("oidc", "access", "refresh"))
                .token(
                        idToken,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                idToken.getClaims()))
                .build();
        this.authorizationService.save(original);

        OAuth2Authorization restored = this.authorizationService.findByToken(
                "id-token", new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        assertAuthorizationDataEquals(original, restored);
        assertAuthorizationDataEquals(
                original, this.authorizationService.findByToken("id-token", null));
        OidcIdToken restoredToken = restored.getToken(OidcIdToken.class).getToken();
        assertEquals(idToken.getClaims(), restoredToken.getClaims());
        assertEquals(issuedAt.minusSeconds(60), restoredToken.getAuthenticatedAt());
        assertEquals("nonce", restoredToken.getNonce());
        assertNull(this.authorizationService.findByToken("id-token", OAuth2TokenType.ACCESS_TOKEN));

        OidcIdToken replacement = new OidcIdToken(
                "new-id-token", issuedAt, issuedAt.plusSeconds(1800), idToken.getClaims());
        this.authorizationService.save(
                OAuth2Authorization.from(restored)
                        .token(
                                replacement,
                                metadata -> metadata.put(
                                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                        replacement.getClaims()))
                        .build());
        assertNull(this.authorizationService.findByToken("id-token", null));
        assertNotNull(
                this.authorizationService.findByToken(
                        "new-id-token", new OAuth2TokenType("id_token")));
    }

    @Test
    void savesFindsUpdatesAndRemovesAuthorization() {
        OAuth2Authorization authorization = authorization("authorization-1", "access-token", "refresh-token");

        this.authorizationService.save(authorization);

        OAuth2Authorization saved = this.authorizationService.findById(authorization.getId());
        assertAuthorizationDataEquals(authorization, saved);
        SecurityIdentity authorizedPrincipal = saved.getAttribute(SecurityIdentity.class.getName());
        assertEquals("resource-owner", authorizedPrincipal.getPrincipal().getName());
        assertEquals(Set.of("user"), authorizedPrincipal.getRoles());
        assertTrue(authorizedPrincipal.getCredentials().isEmpty());
        assertPersistedScopes(authorization.getId(), "message.read");
        assertAuthorizationDataEquals(
                authorization,
                this.authorizationService.findByToken(
                        "access-token", OAuth2TokenType.ACCESS_TOKEN));
        assertAuthorizationDataEquals(
                authorization,
                this.authorizationService.findByToken(
                        "refresh-token", OAuth2TokenType.REFRESH_TOKEN));
        assertAuthorizationDataEquals(
                authorization,
                this.authorizationService.findByToken(
                        "request-state", new OAuth2TokenType(OAuth2ParameterNames.STATE)));
        assertAuthorizationDataEquals(
                authorization,
                this.authorizationService.findByToken(
                        "authorization-code-authorization-1",
                        new OAuth2TokenType(OAuth2ParameterNames.CODE)));
        assertAuthorizationDataEquals(
                authorization, this.authorizationService.findByToken("access-token", null));
        assertNull(this.authorizationService.findByToken("missing-token", null));

        OAuth2Authorization updated = OAuth2Authorization.from(saved).attribute("revision", "updated").build();
        this.authorizationService.save(updated);
        assertEquals(
                "updated",
                this.authorizationService.findById(updated.getId()).getAttribute("revision"));

        this.authorizationService.remove(updated);
        assertNull(this.authorizationService.findById(updated.getId()));
    }

    @Test
    void persistsDecoratedIdentityThroughTheSecurityIdentityContract() throws Exception {
        SecurityIdentity original = QuarkusSecurityIdentity.builder()
                .setPrincipal(() -> "resource-owner")
                .addRole("reader")
                .addAttribute("request-only", "omit")
                .addCredential(new PasswordCredential("secret".toCharArray()))
                .build();
        SecurityIdentity decorated = (SecurityIdentity) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] { SecurityIdentity.class },
                (proxy, method, args) -> method.invoke(original, args));
        OAuth2Authorization authorization = OAuth2Authorization.from(authorization("decorated", "access", "refresh"))
                .attribute(SecurityIdentity.class.getName(), decorated)
                .build();

        this.authorizationService.save(authorization);
        OAuth2Authorization restored = this.authorizationService.findById(authorization.getId());

        SecurityIdentity identity = restored.getAttribute(SecurityIdentity.class.getName());
        assertEquals(QuarkusSecurityIdentity.class, identity.getClass());
        assertEquals("resource-owner", identity.getPrincipal().getName());
        assertEquals(Set.of("reader"), identity.getRoles());
        assertTrue(identity.getCredentials().isEmpty());
        assertTrue(identity.getAttributes().isEmpty());
        assertSame(decorated, authorization.getAttribute(SecurityIdentity.class.getName()));
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void rejectsAnonymousOrMismatchedIdentityBeforeWriting(boolean anonymous) {
        SecurityIdentity invalid = QuarkusSecurityIdentity.builder()
                .setPrincipal(
                        new QuarkusPrincipal(
                                anonymous ? "resource-owner" : "different-user"))
                .setAnonymous(anonymous)
                .build();
        OAuth2Authorization authorization = OAuth2Authorization.from(authorization("invalid-identity", "access", "refresh"))
                .attribute(SecurityIdentity.class.getName(), invalid)
                .build();
        assertThrows(
                IllegalArgumentException.class,
                () -> this.authorizationService.save(authorization));
        assertNull(this.authorizationService.findById(authorization.getId()));
    }

    @Test
    void storesIdentityInsideExistingAttributesAndRejectsMismatchedStoredName() throws Exception {
        OAuth2Authorization authorization = authorization("identity-json", "access", "refresh");
        this.authorizationService.save(authorization);
        try (Connection connection = this.dataSource.getConnection();
                PreparedStatement select = connection.prepareStatement(
                        "SELECT attributes FROM oauth2_authorization WHERE id = ?")) {
            select.setString(1, authorization.getId());
            String json;
            try (ResultSet result = select.executeQuery()) {
                assertTrue(result.next());
                json = result.getString(1);
            }
            assertFalse(json.contains(QuarkusSecurityIdentity.class.getName()));
            assertFalse(json.contains("@class"));
            assertFalse(json.contains("credentials"));
            ObjectNode data = (ObjectNode) new ObjectMapper().readTree(json);
            ObjectNode identity = (ObjectNode) data.path("data").path("identity");
            assertEquals("resource-owner", identity.get("principalName").asText());
            identity.put("principalName", "different-user");
            try (PreparedStatement update = connection.prepareStatement(
                    "UPDATE oauth2_authorization SET attributes = ? WHERE id = ?")) {
                update.setString(1, data.toString());
                update.setString(2, authorization.getId());
                update.executeUpdate();
            }
        }
        assertThrows(
                IllegalArgumentException.class,
                () -> this.authorizationService.findById(authorization.getId()));
    }

    @Test
    void persistsGeneratedRefreshToken() {
        OAuth2RefreshToken refreshToken = new OAuth2RefreshTokenGenerator()
                .generate(
                        DefaultOAuth2TokenContext.builder()
                                .registeredClient(this.registeredClient)
                                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                                .build());
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(this.registeredClient)
                .id("generated-refresh-token-authorization")
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(Set.of("message.read"))
                .refreshToken(refreshToken)
                .build();

        this.authorizationService.save(authorization);

        OAuth2Authorization restored = this.authorizationService.findByToken(
                refreshToken.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN);
        assertNotNull(restored);
        OAuth2RefreshToken storedToken = restored.getRefreshToken().getToken();
        assertEquals(refreshToken.getTokenValue(), storedToken.getTokenValue());
        // H2's default TIMESTAMP rounds to microseconds; the system clock may return nanoseconds.
        assertTrue(Duration.between(refreshToken.getIssuedAt(), storedToken.getIssuedAt()).abs()
                .compareTo(Duration.ofNanos(500)) <= 0);
        assertTrue(Duration.between(refreshToken.getExpiresAt(), storedToken.getExpiresAt()).abs()
                .compareTo(Duration.ofNanos(500)) <= 0);
        assertTrue(restored.getRefreshToken().isActive());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void persistsClientCredentialsProviderResultWithoutResourceOwnerSnapshot(boolean requestScope) {
        RegisteredClient machineClient = RegisteredClient.withId("machine-registration")
                .clientId("machine-client")
                .clientSecret("machine-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("message.read")
                .build();
        JdbcRegisteredClientRepository clientRepository = new JdbcRegisteredClientRepository(this.dataSource);
        clientRepository.save(machineClient);
        SecurityIdentity clientPrincipal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(machineClient.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        machineClient)
                .addAttribute("runtime-only", new Object())
                .build();
        Set<String> scopes = requestScope ? Set.of("message.read") : Set.of();
        Instant issuedAt = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", machineClient.getClientId());
        claims.put("aud", List.of(machineClient.getClientId()));
        claims.put("iat", issuedAt);
        claims.put("exp", issuedAt.plusSeconds(300));
        ClientCredentialsGrant provider = new ClientCredentialsGrant(
                this.authorizationService,
                context -> {
                    // Like JwtGenerator, take the claim's scope collection from the
                    // Provider's token context.
                    if (!context.getAuthorizedScopes().isEmpty()) {
                        claims.put(
                                OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
                    }
                    return new Jwt(
                            "machine-access-token",
                            issuedAt,
                            issuedAt.plusSeconds(300),
                            Map.of("alg", "RS256"),
                            claims);
                },
                new DefaultAuthorizationServerContext(AuthorizationServerSettings.builder()
                        .issuer("https://issuer.example.com")
                        .build()),
                java.util.List.of(context -> {
                }),
                DPoPTestSupport.binding());

        TokenIssuanceResult result = provider.issueTokens(
                new ClientCredentialsRequest(clientPrincipal, scopes, Map.of()));

        clientRepository.save(
                RegisteredClient.from(machineClient)
                        .tokenSettings(
                                TokenSettings.builder()
                                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                                        .build())
                        .build());
        assertEquals(
                OAuth2TokenFormat.REFERENCE,
                clientRepository
                        .findById(machineClient.getId())
                        .getTokenSettings()
                        .getAccessTokenFormat());
        // A fresh service must restore the issued format even after the source client switches
        // formats.
        JdbcOAuth2AuthorizationService reader = new JdbcOAuth2AuthorizationService(this.dataSource, clientRepository);
        OAuth2Authorization restored = reader.findByToken(
                result.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(restored);
        assertEquals(machineClient.getId(), restored.getRegisteredClientId());
        assertEquals(machineClient.getClientId(), restored.getPrincipalName());
        assertEquals(
                AuthorizationGrantType.CLIENT_CREDENTIALS, restored.getAuthorizationGrantType());
        assertEquals(scopes, restored.getAuthorizedScopes());
        assertEquals(scopes, restored.getAccessToken().getToken().getScopes());
        assertEquals(result.getAccessToken(), restored.getAccessToken().getToken());
        assertEquals(issuedAt, restored.getAccessToken().getToken().getIssuedAt());
        assertEquals(
                issuedAt.plusSeconds(300), restored.getAccessToken().getToken().getExpiresAt());
        assertEquals(claims, restored.getAccessToken().getClaims());
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED.getValue(),
                restored.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertTrue(restored.getAccessToken().isActive());
        assertTrue(restored.getAttributes().isEmpty());
        assertNull(restored.getRefreshToken());
        assertNull(restored.getToken(OidcIdToken.class));
        assertPersistedScopes(restored.getId(), requestScope ? "message.read" : null);
    }

    @Test
    void persistsAndRestoresGeneratedReferenceTokenAndClaims() {
        RegisteredClient machineClient = RegisteredClient.withId("opaque-registration")
                .clientId("opaque-client")
                .clientSecret("opaque-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("message.read")
                .tokenSettings(
                        TokenSettings.builder()
                                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                                .accessTokenTimeToLive(Duration.ofMinutes(4))
                                .build())
                .build();
        JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(this.dataSource);
        clients.save(machineClient);
        SecurityIdentity principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(machineClient.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        machineClient)
                .build();
        ClientCredentialsGrant provider = new ClientCredentialsGrant(
                this.authorizationService,
                new OAuth2AccessTokenGenerator(),
                new DefaultAuthorizationServerContext(AuthorizationServerSettings.builder()
                        .issuer("https://issuer.example")
                        .build()),
                java.util.List.of(context -> {
                }),
                DPoPTestSupport.binding());

        TokenIssuanceResult result = provider.issueTokens(
                new ClientCredentialsRequest(principal, Set.of("message.read"), Map.of()));

        clients.save(
                RegisteredClient.from(machineClient)
                        .tokenSettings(
                                TokenSettings.builder()
                                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                                        .build())
                        .build());
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED,
                clients.findById(machineClient.getId()).getTokenSettings().getAccessTokenFormat());
        OAuth2Authorization restored = new JdbcOAuth2AuthorizationService(this.dataSource, clients)
                .findByToken(
                        result.getAccessToken().getTokenValue(),
                        OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(restored);
        assertEquals(
                OAuth2TokenFormat.REFERENCE,
                machineClient.getTokenSettings().getAccessTokenFormat());
        assertEquals(
                OAuth2TokenFormat.REFERENCE.getValue(),
                restored.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertEquals("opaque-client", restored.getPrincipalName());
        assertEquals(Set.of("message.read"), restored.getAuthorizedScopes());
        assertEquals("opaque-client", restored.getAccessToken().getClaims().get("sub"));
        assertEquals(List.of("opaque-client"), restored.getAccessToken().getClaims().get("aud"));
        assertEquals(
                Duration.ofMinutes(4),
                Duration.between(
                        restored.getAccessToken().getToken().getIssuedAt(),
                        restored.getAccessToken().getToken().getExpiresAt()));
        assertTrue(restored.getAccessToken().isActive());
    }

    @Test
    void persistsTokenExchangeCompositeIdentityClaimsAndScopes() {
        RegisteredClient exchangeClient = RegisteredClient.withId("exchange-registration")
                .clientId("exchange-client")
                .clientSecret("exchange-secret")
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scope("message.read")
                .build();
        JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(this.dataSource);
        clients.save(exchangeClient);
        SecurityIdentity principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                .addRoles(Set.of("user"))
                .addAttribute(
                        OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE,
                        List.of(
                                Map.of("sub", "current-actor"),
                                Map.of("sub", "previous-actor")))
                .build();
        Instant issuedAt = Instant.parse("2026-09-04T04:00:00Z");
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "exchange-access-token",
                issuedAt,
                issuedAt.plusSeconds(300),
                Set.of("message.read"));
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "resource-owner");
        claims.put("aud", List.of("messages-api"));
        claims.put("act", Map.of("sub", "current-actor", "act", Map.of("sub", "previous-actor")));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(exchangeClient)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizedScopes(Set.of("message.read"))
                .attribute(SecurityIdentity.class.getName(), principal)
                .token(
                        accessToken,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                claims))
                .build();

        this.authorizationService.save(authorization);

        OAuth2Authorization restored = new JdbcOAuth2AuthorizationService(this.dataSource, clients)
                .findByToken(accessToken.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(restored);
        assertEquals(AuthorizationGrantType.TOKEN_EXCHANGE, restored.getAuthorizationGrantType());
        assertEquals(Set.of("message.read"), restored.getAuthorizedScopes());
        assertEquals(claims, restored.getAccessToken().getClaims());
        assertEquals(accessToken, restored.getAccessToken().getToken());
        SecurityIdentity restoredPrincipal = restored.getAttribute(SecurityIdentity.class.getName());
        assertEquals(principal.getRoles(), restoredPrincipal.getRoles());
        assertEquals("resource-owner", restoredPrincipal.getPrincipal().getName());
        assertEquals(
                List.of("current-actor", "previous-actor"),
                OAuth2TokenExchangeTokenCustomizers.getActors(restoredPrincipal).stream()
                        .map(actor -> actor.get("sub"))
                        .toList());
        assertPersistedScopes(restored.getId(), "message.read");
    }

    @Test
    void persistsRefreshTokenRevocationCascadeAcrossServiceInstances() {
        OAuth2Authorization authorization = authorization(
                "revoked-authorization", "revoked-access-token", "revoked-refresh-token");
        this.authorizationService.save(authorization);
        SecurityIdentity clientPrincipal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(this.registeredClient.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        this.registeredClient)
                .build();

        new OAuth2TokenRevocationAuthenticationProvider(this.authorizationService)
                .authenticate(
                        new OAuth2TokenRevocationAuthenticationToken(
                                "revoked-refresh-token",
                                clientPrincipal,
                                OAuth2TokenType.ACCESS_TOKEN.getValue()));

        JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(this.dataSource);
        OAuth2Authorization restored = new JdbcOAuth2AuthorizationService(this.dataSource, clients)
                .findByToken("revoked-refresh-token", null);
        assertNotNull(restored);
        assertTrue(restored.getRefreshToken().isInvalidated());
        assertTrue(restored.getAccessToken().isInvalidated());
        assertTrue(restored.getAuthorizationCode().isInvalidated());
        assertPersistedScopes(restored.getId(), "message.read");
    }

    @Test
    void replacesRefreshTokenAndRemovesPreviousValueFromLookup() {
        OAuth2Authorization authorization = authorization(
                "rotated-refresh-token-authorization",
                "access-token",
                "previous-refresh-token");
        this.authorizationService.save(authorization);
        Instant issuedAt = Instant.parse("2026-09-01T01:00:00.123456Z");
        OAuth2RefreshToken rotatedRefreshToken = new OAuth2RefreshToken(
                "rotated-refresh-token", issuedAt, issuedAt.plusSeconds(3600));

        OAuth2Authorization rotatedAuthorization = OAuth2Authorization.from(authorization).refreshToken(rotatedRefreshToken)
                .build();
        this.authorizationService.save(rotatedAuthorization);

        assertNull(
                this.authorizationService.findByToken(
                        "previous-refresh-token", OAuth2TokenType.REFRESH_TOKEN));
        assertAuthorizationDataEquals(
                rotatedAuthorization,
                this.authorizationService.findByToken(
                        rotatedRefreshToken.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN));
    }

    @Test
    void persistsAndRestoresDeviceAndUserCodesWithMetadata() {
        Instant issuedAt = Instant.parse("2026-09-04T01:00:00Z");
        OAuth2DeviceCode deviceCode = new OAuth2DeviceCode("device-code", issuedAt, issuedAt.plusSeconds(420));
        OAuth2UserCode userCode = new OAuth2UserCode("BCDF-GHJK", issuedAt, issuedAt.plusSeconds(420));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(this.registeredClient)
                .id("device-authorization")
                .principalName(this.registeredClient.getClientId())
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .attribute(
                        OAuth2ParameterNames.SCOPE,
                        new java.util.LinkedHashSet<>(Set.of("message.read")))
                .token(deviceCode, metadata -> metadata.put("device-detail", "value"))
                .token(
                        userCode,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                true))
                .build();

        this.authorizationService.save(authorization);

        JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(this.dataSource);
        JdbcOAuth2AuthorizationService reader = new JdbcOAuth2AuthorizationService(this.dataSource, clients);
        OAuth2Authorization restoredByDeviceCode = reader.findByToken(
                deviceCode.getTokenValue(),
                new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE));
        OAuth2Authorization restoredByUserCode = reader.findByToken(
                userCode.getTokenValue(),
                new OAuth2TokenType(OAuth2ParameterNames.USER_CODE));

        assertNotNull(restoredByDeviceCode);
        assertEquals(restoredByDeviceCode, restoredByUserCode);
        assertEquals(
                AuthorizationGrantType.DEVICE_CODE,
                restoredByDeviceCode.getAuthorizationGrantType());
        assertEquals(
                Set.of("message.read"),
                restoredByDeviceCode.getAttribute(OAuth2ParameterNames.SCOPE));
        assertTrue(restoredByDeviceCode.getAuthorizedScopes().isEmpty());
        assertEquals(deviceCode, restoredByDeviceCode.getToken(OAuth2DeviceCode.class).getToken());
        assertEquals(
                "value",
                restoredByDeviceCode.getToken(OAuth2DeviceCode.class).getMetadata("device-detail"));
        assertEquals(userCode, restoredByDeviceCode.getToken(OAuth2UserCode.class).getToken());
        assertTrue(restoredByDeviceCode.getToken(OAuth2UserCode.class).isInvalidated());
        assertEquals(restoredByDeviceCode, reader.findByToken(deviceCode.getTokenValue(), null));
        assertEquals(restoredByDeviceCode, reader.findByToken(userCode.getTokenValue(), null));
    }

    @Test
    void rollsBackAuthorizationWhenUniqueAccessTokenIsViolated() {
        OAuth2Authorization first = authorization("authorization-1", "shared-access-token", "refresh-token-1");
        OAuth2Authorization duplicate = authorization("authorization-2", "shared-access-token", "refresh-token-2");
        this.authorizationService.save(first);

        assertThrows(IllegalStateException.class, () -> this.authorizationService.save(duplicate));

        assertAuthorizationDataEquals(first, this.authorizationService.findById(first.getId()));
        assertNull(this.authorizationService.findById(duplicate.getId()));
    }

    @Test
    void persistsCustomValuesWithAnExplicitCodecAcrossRepositoryInstances() {
        JdbcRegisteredClientRepository clients = new JdbcRegisteredClientRepository(this.dataSource);
        JdbcOAuth2AuthorizationService writer = new JdbcOAuth2AuthorizationService(this.dataSource, clients,
                JdbcTestSupport.jsonCodec());
        OAuth2Authorization authorization = OAuth2Authorization
                .from(authorization("custom-codec", "custom-access", "custom-refresh"))
                .attribute("custom", new JdbcTestSupport.CustomValue("custom-data"))
                .build();
        writer.save(authorization);
        JdbcOAuth2AuthorizationService reader = new JdbcOAuth2AuthorizationService(this.dataSource, clients,
                JdbcTestSupport.jsonCodec());
        assertAuthorizationDataEquals(authorization, reader.findById(authorization.getId()));
        assertThrows(IllegalArgumentException.class, () -> this.authorizationService.findById(authorization.getId()));
        assertThrows(NullPointerException.class, () -> new JdbcOAuth2AuthorizationService(this.dataSource, clients, null));
    }

    @Test
    void futureNotBeforeRemainsInactiveAfterJdbcReplay() {
        Instant now = Instant.now();
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "future-access", now,
                now.plusSeconds(3600), Set.of("read"));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(this.registeredClient)
                .principalName("resource-owner").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(token, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                        Map.of("sub", "resource-owner", "nbf", now.plusSeconds(600))))
                .build();
        this.authorizationService.save(authorization);
        var reader = new JdbcOAuth2AuthorizationService(this.dataSource, new JdbcRegisteredClientRepository(this.dataSource));
        var restored = reader.findById(authorization.getId()).getAccessToken();
        assertFalse(restored.isExpired());
        assertTrue(restored.isBeforeUse());
        assertFalse(restored.isActive());
    }

    @Test
    void persistsAuthorizationRequestAttribute() {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com/oauth2/authorize")
                .clientId("messaging-client")
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .state("request-state")
                .additionalParameters(
                        parameters -> {
                            parameters.put("code_challenge", "challenge");
                            parameters.put("code_challenge_method", "S256");
                        })
                .attributes(attributes -> attributes.put("request-id", "request-1"))
                .build();
        OAuth2Authorization authorization = OAuth2Authorization.from(
                authorization(
                        "authorization-request", "access-token", "refresh-token"))
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .build();

        this.authorizationService.save(authorization);

        OAuth2Authorization restored = this.authorizationService.findById(authorization.getId());
        OAuth2AuthorizationRequest restoredRequest = restored.getAttribute(OAuth2AuthorizationRequest.class.getName());
        assertNotNull(restoredRequest);
        assertEquals(
                authorizationRequest.getAuthorizationUri(), restoredRequest.getAuthorizationUri());
        assertEquals(authorizationRequest.getGrantType(), restoredRequest.getGrantType());
        assertEquals(authorizationRequest.getResponseType(), restoredRequest.getResponseType());
        assertEquals(authorizationRequest.getClientId(), restoredRequest.getClientId());
        assertEquals(authorizationRequest.getRedirectUri(), restoredRequest.getRedirectUri());
        assertEquals(authorizationRequest.getScopes(), restoredRequest.getScopes());
        assertEquals(authorizationRequest.getState(), restoredRequest.getState());
        assertEquals(
                authorizationRequest.getAdditionalParameters(),
                restoredRequest.getAdditionalParameters());
        assertEquals(
                authorizationRequest.getAuthorizationRequestUri(),
                restoredRequest.getAuthorizationRequestUri());
        assertEquals(authorizationRequest.getAttributes(), restoredRequest.getAttributes());
    }

    @Test
    void replacesConsentStateWithAuthorizationCode() {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com/oauth2/authorize")
                .clientId("messaging-client")
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .state("client-state")
                .build();
        OAuth2Authorization inFlightAuthorization = OAuth2Authorization.withRegisteredClient(this.registeredClient)
                .id("consent-authorization")
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(OAuth2ParameterNames.STATE, "internal-consent-state")
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .build();
        this.authorizationService.save(inFlightAuthorization);

        Instant issuedAt = Instant.parse("2026-09-01T01:00:00Z");
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "generated-authorization-code", issuedAt, issuedAt.plusSeconds(300));
        OAuth2Authorization completedAuthorization = OAuth2Authorization.from(inFlightAuthorization)
                .authorizedScopes(Set.of("message.read"))
                .authorizationCode(authorizationCode)
                .attributes(attributes -> attributes.remove(OAuth2ParameterNames.STATE))
                .build();
        this.authorizationService.save(completedAuthorization);

        assertNull(
                this.authorizationService.findByToken(
                        "internal-consent-state", new OAuth2TokenType(OAuth2ParameterNames.STATE)));
        OAuth2Authorization restored = this.authorizationService.findByToken(
                authorizationCode.getTokenValue(),
                new OAuth2TokenType(OAuth2ParameterNames.CODE));
        assertNotNull(restored);
        assertEquals(Set.of("message.read"), restored.getAuthorizedScopes());
        assertEquals(authorizationCode, restored.getAuthorizationCode().getToken());
        assertNull(restored.getAttribute(OAuth2ParameterNames.STATE));
    }

    @Test
    void persistsAuthorizationCodeExchangeAndInvalidation() {
        Instant issuedAt = Instant.parse("2026-09-01T02:00:00Z");
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com/oauth2/authorize")
                .clientId("messaging-client")
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .additionalParameters(
                        parameters -> {
                            parameters.put("code_challenge", "challenge");
                            parameters.put("code_challenge_method", "S256");
                        })
                .build();
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "exchanged-authorization-code", issuedAt, issuedAt.plusSeconds(300));
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "authorization-code-access-token",
                issuedAt,
                issuedAt.plusSeconds(300),
                Set.of("message.read"));
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "resource-owner");
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(this.registeredClient)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("message.read"))
                .attribute(
                        SecurityIdentity.class.getName(),
                        QuarkusSecurityIdentity.builder()
                                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                                .addRoles(Set.of("user"))
                                .build())
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .token(
                        authorizationCode,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                true))
                .token(
                        accessToken,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                claims))
                .build();

        this.authorizationService.save(authorization);

        OAuth2Authorization restored = this.authorizationService.findByToken(
                authorizationCode.getTokenValue(),
                new OAuth2TokenType(OAuth2ParameterNames.CODE));
        assertNotNull(restored);
        assertTrue(restored.getAuthorizationCode().isInvalidated());
        assertEquals(accessToken, restored.getAccessToken().getToken());
        assertEquals(claims, restored.getAccessToken().getClaims());
        assertPersistedScopes(restored.getId(), "message.read");
    }

    private static void assertAuthorizationDataEquals(
            OAuth2Authorization expected, OAuth2Authorization actual) {
        assertNotNull(actual);
        assertEquals(
                OAuth2Authorization.from(expected)
                        .attributes(values -> values.remove(SecurityIdentity.class.getName()))
                        .build(),
                OAuth2Authorization.from(actual)
                        .attributes(values -> values.remove(SecurityIdentity.class.getName()))
                        .build());
        SecurityIdentity expectedIdentity = expected.getAttribute(SecurityIdentity.class.getName());
        SecurityIdentity actualIdentity = actual.getAttribute(SecurityIdentity.class.getName());
        if (expectedIdentity == null) {
            assertNull(actualIdentity);
        } else {
            assertEquals(
                    expectedIdentity.getPrincipal().getName(),
                    actualIdentity.getPrincipal().getName());
            assertEquals(expectedIdentity.getRoles(), actualIdentity.getRoles());
            assertEquals(expectedIdentity.getAttributes(), actualIdentity.getAttributes());
        }
    }

    private OAuth2Authorization authorization(
            String id, String accessTokenValue, String refreshTokenValue) {
        Instant issuedAt = Instant.parse("2026-08-31T01:00:00Z");
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("requested_at", issuedAt);
        context.put("timeout", Duration.ofSeconds(30));
        context.put("audiences", new ArrayList<>(List.of("messages")));
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "resource-owner");
        claims.put("iat", issuedAt);
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                accessTokenValue,
                issuedAt,
                issuedAt.plusSeconds(300),
                Set.of("message.read"));
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refreshTokenValue, issuedAt, issuedAt.plusSeconds(3600));
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "authorization-code-" + id, issuedAt, issuedAt.plusSeconds(300));
        return OAuth2Authorization.withRegisteredClient(this.registeredClient)
                .id(id)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(Set.of("message.read"))
                .attribute(
                        SecurityIdentity.class.getName(),
                        QuarkusSecurityIdentity.builder()
                                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                                .addRoles(Set.of("user"))
                                .build())
                .attribute(OAuth2ParameterNames.STATE, "request-state")
                .attribute("context", context)
                .authorizationCode(authorizationCode)
                .token(
                        accessToken,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims))
                .refreshToken(refreshToken)
                .build();
    }

    private void assertPersistedScopes(String authorizationId, String expectedScopes) {
        try (Connection connection = this.dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement(
                        "SELECT authorized_scopes, access_token_scopes FROM"
                                + " oauth2_authorization WHERE id = ?")) {
            statement.setString(1, authorizationId);
            try (ResultSet resultSet = statement.executeQuery()) {
                assertTrue(resultSet.next());
                assertEquals(expectedScopes, resultSet.getString("authorized_scopes"));
                assertEquals(expectedScopes, resultSet.getString("access_token_scopes"));
            }
        } catch (SQLException exception) {
            throw new AssertionError(exception);
        }
    }
}
