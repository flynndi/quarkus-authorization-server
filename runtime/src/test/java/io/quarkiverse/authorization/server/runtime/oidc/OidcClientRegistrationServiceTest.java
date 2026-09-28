package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.ClientSecretEncoder;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequest;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.runtime.client.BcryptClientSecretVerifier;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTestSupport;
import io.quarkiverse.authorization.server.runtime.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import io.quarkiverse.authorization.server.runtime.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientConfigurationRequest;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientConfigurationService;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientRegistrationService;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.runtime.token.ConfiguredAuthorizationServerKeySource;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OidcClientRegistrationServiceTest {
    private static final AuthorizationServerSettings SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example/api/")
            .oidcClientRegistrationEndpoint("/clients")
            .build();
    private static final AuthorizationServerKeyManager KEYS = new AuthorizationServerKeyManager(
            new ConfiguredAuthorizationServerKeySource(
                    new AuthorizationServerRuntimeConfig() {
                        public java.util.Map<String, String> issuers() {
                            return java.util.Map.of();
                        }

                        @Override
                        public DPoPConfig dpop() {
                            throw new UnsupportedOperationException("Signing fixture does not use DPoP");
                        }

                        @Override
                        public Optional<String> issuer() {
                            return Optional.empty();
                        }

                        @Override
                        public Map<String, RegisteredClientConfig> clients() {
                            return Map.of();
                        }

                        @Override
                        public SigningConfig signing() {
                            return new SigningConfig() {
                                @Override
                                public Optional<String> activeKeyId() {
                                    return Optional.empty();
                                }

                                @Override
                                public Map<String, SigningKeyConfig> keys() {
                                    return Map.of();
                                }

                                @Override
                                public String algorithm() {
                                    return "RS256";
                                }

                                @Override
                                public Optional<String> keyId() {
                                    return Optional.empty();
                                }

                                @Override
                                public Optional<String> privateKeyLocation() {
                                    return Optional.empty();
                                }

                                @Override
                                public Optional<String> publicKeyLocation() {
                                    return Optional.empty();
                                }
                            };
                        }
                    }));
    private JdbcDataSource dataSource;
    private JdbcRegisteredClientRepository clients;
    private JdbcOAuth2AuthorizationService service;
    private OidcClientRegistrationService provider;
    private OidcClientConfigurationService reader;
    private final AtomicReference<OAuth2TokenContext> generatedContext = new AtomicReference<>();

    @BeforeEach
    void setUp() {
        this.dataSource = new JdbcDataSource();
        this.dataSource.setURL(
                "jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE");
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        JdbcTestSupport.executeSchema(
                this.dataSource, JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        this.clients = new JdbcRegisteredClientRepository(this.dataSource);
        this.service = new JdbcOAuth2AuthorizationService(this.dataSource, this.clients);
        var bootstrap = RegisteredClient.withId("bootstrap")
                .clientId("bootstrap")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        this.clients.save(bootstrap);
        initial(Set.of("client.create"), false, Instant.now().plusSeconds(300));
        this.provider = provider(
                context -> {
                    this.generatedContext.set(context);
                    return new Jwt(
                            "registration-token-" + UUID.randomUUID(),
                            Instant.now(),
                            Instant.now().plusSeconds(300),
                            Map.of("alg", "RS256"),
                            Map.of(
                                    "sub",
                                    context.getPrincipal().getPrincipal().getName(),
                                    "scope",
                                    context.getAuthorizedScopes()));
                });
        this.reader = new OidcClientConfigurationService(
                this.clients,
                this.service,
                new DefaultAuthorizationServerContext(SETTINGS),
                new RegisteredClientOidcClientRegistrationConverter()::map);
    }

    @Test
    void registersPersistsEncodesAndReadsOnlyTheBoundClientAfterJdbcReplay() throws Exception {
        var response = this.provider.register(request());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertEquals(
                "https://issuer.example/api/clients?client_id=" + response.getClientId(),
                response.getRegistrationClientUrl().toString());
        var persisted = new JdbcRegisteredClientRepository(this.dataSource)
                .findByClientId(response.getClientId());
        assertNotEquals(response.getClientSecret(), persisted.getClientSecret());
        assertTrue(
                new BcryptClientSecretVerifier()
                        .matches(response.getClientSecret(), persisted.getClientSecret()));
        assertTrue(persisted.getClientSettings().isRequireProofKey());
        var authorization = this.service.findByToken(
                response.getRegistrationAccessToken(), OAuth2TokenType.ACCESS_TOKEN);
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED.getValue(),
                authorization.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertEquals(persisted.getId(), authorization.getRegisteredClientId());
        assertEquals(Set.of("client.read"), authorization.getAuthorizedScopes());
        assertEquals(Set.of("client.read"), authorization.getAccessToken().getToken().getScopes());
        assertEquals(
                AuthorizationGrantType.CLIENT_CREDENTIALS,
                authorization.getAuthorizationGrantType());
        assertEquals(
                persisted.getClientId(),
                this.generatedContext.get().getPrincipal().getPrincipal().getName());
        assertEquals(OAuth2TokenType.ACCESS_TOKEN, this.generatedContext.get().getTokenType());
        assertEquals(
                AuthorizationGrantType.CLIENT_CREDENTIALS,
                this.generatedContext.get().getAuthorizationGrantType());
        assertFalse(this.service.findById("initial-authorization").getAccessToken().isActive());
        assertFalse(this.service.findById("initial-authorization").getRefreshToken().isActive());
        var replayReader = new OidcClientConfigurationService(
                new JdbcRegisteredClientRepository(this.dataSource),
                new JdbcOAuth2AuthorizationService(this.dataSource, this.clients),
                new DefaultAuthorizationServerContext(SETTINGS),
                new RegisteredClientOidcClientRegistrationConverter()::map);
        var config = replayReader.read(read(response));
        assertEquals(response.getClientId(), config.getClientId());
        assertEquals(response.getRegistrationClientUrl(), config.getRegistrationClientUrl());
        assertNull(config.getClientSecret());
        assertNull(config.getClientSecretExpiresAt());
        assertNull(config.getRegistrationAccessToken());
        assertError("invalid_token", () -> this.provider.register(request()));
        assertEquals(2, clientCount());
    }

    @Test
    void keepsPublicRegistrationSecretlessAndDoesNotPermitTokenScopeReuse() {
        var publicRequest = new OidcClientRegistrationRequest(
                identity("bootstrap", "initial"),
                metadata().tokenEndpointAuthenticationMethod("none").build());
        var response = this.provider.register(publicRequest);
        assertNull(response.getClientSecret());
        assertNull(this.clients.findByClientId(response.getClientId()).getClientSecret());
        assertNotNull(this.reader.read(read(response)));
        assertError(
                "insufficient_scope",
                () -> this.provider.register(
                        new OidcClientRegistrationRequest(
                                identity(
                                        response.getClientId(),
                                        response.getRegistrationAccessToken()),
                                metadata().build())));
        assertError(
                "invalid_client",
                () -> this.reader.read(
                        new OidcClientConfigurationRequest(
                                identity(
                                        response.getClientId(),
                                        response.getRegistrationAccessToken()),
                                "bootstrap")));
        assertError(
                "invalid_client",
                () -> this.reader.read(
                        new OidcClientConfigurationRequest(
                                identity(
                                        response.getClientId(),
                                        response.getRegistrationAccessToken()),
                                "missing")));
    }

    @Test
    void checksAuthoritativeTokenScopesStateAndPrincipal() {
        for (Set<String> scopes : Set.of(Set.of("message.read"), Set.<String> of(), Set.of("client.read"))) {
            initial(scopes, false, Instant.now().plusSeconds(300));
            assertError("insufficient_scope", () -> this.provider.register(request()));
        }
        initial(Set.of("client.create", "message.read"), false, Instant.now().plusSeconds(300));
        assertError("invalid_token", () -> this.provider.register(request()));
        initial(Set.of("client.create"), true, Instant.now().plusSeconds(300));
        assertError("invalid_token", () -> this.provider.register(request()));
        initial(Set.of("client.create"), false, Instant.now().minusSeconds(1));
        assertError("invalid_token", () -> this.provider.register(request()));
        initial(Set.of("client.create"), false, Instant.now().plusSeconds(300));
        assertError(
                "invalid_token",
                () -> this.provider.register(
                        new OidcClientRegistrationRequest(
                                identity("other", "initial"), metadata().build())));
        assertError(
                "invalid_token",
                () -> this.provider.register(
                        new OidcClientRegistrationRequest(
                                identity("bootstrap", "initial-refresh"),
                                metadata().build())));
        assertError(
                "invalid_token",
                () -> this.provider.register(
                        new OidcClientRegistrationRequest(
                                QuarkusSecurityIdentity.builder()
                                        .setAnonymous(true)
                                        .build(),
                                metadata().build())));
    }

    @Test
    void rejectsInvalidMetadataAndGeneratorFailureBeforeWritingOrConsumingInitialToken()
            throws Exception {
        assertError(
                "invalid_client_metadata",
                () -> this.provider.register(
                        new OidcClientRegistrationRequest(
                                identity("bootstrap", "initial"),
                                metadata().scope("client.create").build())));
        assertError("server_error", () -> provider(context -> null).register(request()));
        assertError(
                "server_error",
                () -> provider(
                        context -> new OAuth2RefreshToken(
                                "wrong-type", Instant.now(), null))
                        .register(request()));
        assertError(
                "server_error",
                () -> provider(
                        context -> new OAuth2AccessToken(
                                OAuth2AccessToken.TokenType.BEARER,
                                "expired",
                                Instant.now().minusSeconds(60),
                                Instant.now().minusSeconds(1),
                                Set.of("client.read")))
                        .register(request()));
        var insecureEncoder = provider(this.service, context -> null, secret -> secret);
        assertError("server_error", () -> insecureEncoder.register(request()));
        assertEquals(1, clientCount());
        assertTrue(this.service.findById("initial-authorization").getAccessToken().isActive());
    }

    @Test
    void sanitizesConfigurationEvenAfterCustomResponseConversion() {
        var response = this.provider.register(request());
        var reader = new OidcClientConfigurationService(
                this.clients,
                this.service,
                new DefaultAuthorizationServerContext(SETTINGS),
                client -> {
                    assertNull(client.getClientSecret());
                    return OidcClientRegistration.withClaims(
                            new RegisteredClientOidcClientRegistrationConverter()
                                    .map(client)
                                    .getClaims())
                            .clientSecret("should-not-escape")
                            .registrationAccessToken("should-not-escape")
                            .clientSecretExpiresAt(Instant.now().plusSeconds(60))
                            .claim("custom", "retained")
                            .build();
                });
        var config = reader.read(read(response));
        assertNull(config.getClientSecret());
        assertNull(config.getRegistrationAccessToken());
        assertEquals("retained", config.getClaim("custom"));
    }

    @Test
    void servicesRequireTheirTypedRequests() {
        assertThrows(NullPointerException.class, () -> this.provider.register(null));
        assertThrows(NullPointerException.class, () -> this.reader.read(null));
    }

    @Test
    void registrationAuthorizationSaveFailureLeavesCommittedClientAndActiveInitialToken()
            throws Exception {
        assertPartialCommit(false);
    }

    @Test
    void configurationReadsRejectExpiredInvalidatedAndMixedScopeRegistrationTokens() {
        var registration = this.provider.register(request());
        var authorization = this.service.findByToken(
                registration.getRegistrationAccessToken(), OAuth2TokenType.ACCESS_TOKEN);
        var token = authorization.getAccessToken().getToken();
        this.service.save(
                OAuth2Authorization.from(authorization)
                        .token(
                                token,
                                metadata -> metadata.put(
                                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                        true))
                        .build());
        assertError("invalid_token", () -> this.reader.read(read(registration)));
        this.service.save(
                OAuth2Authorization.from(authorization)
                        .accessToken(
                                new OAuth2AccessToken(
                                        token.getTokenType(),
                                        token.getTokenValue(),
                                        Instant.now().minusSeconds(60),
                                        Instant.now().minusSeconds(1),
                                        token.getScopes()))
                        .build());
        assertError("invalid_token", () -> this.reader.read(read(registration)));
        this.service.save(
                OAuth2Authorization.from(authorization)
                        .accessToken(
                                new OAuth2AccessToken(
                                        token.getTokenType(),
                                        token.getTokenValue(),
                                        token.getIssuedAt(),
                                        token.getExpiresAt(),
                                        Set.of("client.read", "openid")))
                        .build());
        assertError("invalid_token", () -> this.reader.read(read(registration)));
        this.service.save(
                OAuth2Authorization.from(authorization)
                        .accessToken(
                                new OAuth2AccessToken(
                                        token.getTokenType(),
                                        token.getTokenValue(),
                                        token.getIssuedAt(),
                                        token.getExpiresAt(),
                                        Set.of("openid")))
                        .build());
        assertError("insufficient_scope", () -> this.reader.read(read(registration)));
    }

    @Test
    void initialInvalidationSaveFailureLeavesCommittedClientAndRegistrationToken()
            throws Exception {
        assertPartialCommit(true);
    }

    private void assertPartialCommit(boolean failInvalidation) throws Exception {
        var token = new AtomicReference<String>();
        OAuth2AuthorizationService failing = new ObservedAuthorizationService(
                this.service,
                authorization -> {
                    if ("initial-authorization".equals(authorization.getId()) == failInvalidation) {
                        throw new IllegalStateException(
                                "Injected authorization storage failure");
                    }
                },
                UnaryOperator.identity());
        var provider = provider(
                failing,
                context -> {
                    token.set("registration-" + UUID.randomUUID());
                    return new OAuth2AccessToken(
                            OAuth2AccessToken.TokenType.BEARER,
                            token.get(),
                            Instant.now(),
                            Instant.now().plusSeconds(300),
                            context.getAuthorizedScopes());
                });
        assertThrows(IllegalStateException.class, () -> provider.register(request()));
        // Characterize the current contract: a failed response does not imply rolled-back storage.
        assertEquals(2, clientCount());
        assertTrue(this.service.findById("initial-authorization").getAccessToken().isActive());
        assertTrue(this.service.findById("initial-authorization").getRefreshToken().isActive());
        var saved = this.service.findByToken(token.get(), OAuth2TokenType.ACCESS_TOKEN);
        if (failInvalidation) {
            assertNotNull(saved);
            assertTrue(saved.getAccessToken().isActive());
            assertNotNull(this.clients.findById(saved.getRegisteredClientId()));
        } else {
            assertNull(saved);
        }
    }

    @Test
    void concurrentInitialTokenReadsCanRegisterTwoClientsWithoutCompareAndSet() throws Exception {
        CyclicBarrier snapshotsRead = new CyclicBarrier(2);
        OAuth2AuthorizationService observed = new ObservedAuthorizationService(
                this.service,
                authorization -> {
                },
                authorization -> {
                    if (authorization != null
                            && "initial-authorization".equals(authorization.getId())) {
                        try {
                            // Both independent Providers see the same active snapshot
                            // before either invalidates it.
                            snapshotsRead.await(5, TimeUnit.SECONDS);
                        } catch (Exception exception) {
                            throw new IllegalStateException(
                                    "Unable to coordinate the two authorization reads",
                                    exception);
                        }
                    }
                    return authorization;
                });
        OAuth2TokenGenerator<OAuth2AccessToken> generator = context -> new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                UUID.randomUUID().toString(),
                Instant.now(),
                Instant.now().plusSeconds(300),
                context.getAuthorizedScopes());
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> provider(observed, generator).register(request()));
            var second = executor.submit(() -> provider(observed, generator).register(request()));
            var firstRegistration = first.get(10, TimeUnit.SECONDS);
            var secondRegistration = second.get(10, TimeUnit.SECONDS);
            assertNotEquals(firstRegistration.getClientId(), secondRegistration.getClientId());
            assertEquals(3, clientCount());
            assertFalse(this.service.findById("initial-authorization").getAccessToken().isActive());
            assertNotNull(this.reader.read(read(firstRegistration)));
            assertNotNull(this.reader.read(read(secondRegistration)));
        }
    }

    /** Test-only observation/fault injection around the real JDBC service. */
    private record ObservedAuthorizationService(
            OAuth2AuthorizationService delegate,
            Consumer<OAuth2Authorization> beforeSave,
            UnaryOperator<OAuth2Authorization> afterRead)
            implements
                OAuth2AuthorizationService {
        @Override
        public void save(OAuth2Authorization authorization) {
            this.beforeSave.accept(authorization);
            this.delegate.save(authorization);
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
            this.delegate.remove(authorization);
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return this.delegate.findById(id);
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
            return this.afterRead.apply(this.delegate.findByToken(token, type));
        }
    }

    private static OidcClientRegistrationRequestValidator registrationValidator() {
        return OidcClientRegistrationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                .andThen(OidcClientRegistrationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
                .andThen(
                        context -> {
                            var scopes = context.request().getClientRegistration().getScopes();
                            if (scopes != null
                                    && !Set.of("openid", "profile", "message.read")
                                            .containsAll(scopes)) {
                                throw new OAuth2AuthenticationException("invalid_scope");
                            }
                        });
    }

    private OidcClientRegistrationService provider(
            OAuth2TokenGenerator<? extends OAuth2Token> generator) {
        return provider(this.service, generator);
    }

    private OidcClientRegistrationService provider(
            OAuth2AuthorizationService service,
            OAuth2TokenGenerator<? extends OAuth2Token> generator) {
        return provider(service, generator, secret -> BcryptUtil.bcryptHash(secret, 4));
    }

    private OidcClientRegistrationService provider(
            OAuth2AuthorizationService service,
            OAuth2TokenGenerator<? extends OAuth2Token> generator,
            ClientSecretEncoder encoder) {
        var result = new OidcClientRegistrationService(
                this.clients,
                service,
                generator,
                new DefaultAuthorizationServerContext(SETTINGS),
                KEYS,
                registrationValidator(),
                new OidcClientRegistrationRegisteredClientConverter(
                        KEYS.getSigningAlgorithms(), settings -> {
                        }, settings -> {
                        })::convert,
                new RegisteredClientOidcClientRegistrationConverter()::map,
                encoder);
        return result;
    }

    private void initial(Set<String> scopes, boolean invalidated, Instant expiresAt) {
        this.service.save(
                OAuth2Authorization.withRegisteredClient(this.clients.findById("bootstrap"))
                        .id("initial-authorization")
                        .principalName("bootstrap")
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .authorizedScopes(scopes)
                        .token(
                                new OAuth2AccessToken(
                                        OAuth2AccessToken.TokenType.BEARER,
                                        "initial",
                                        Instant.now().minusSeconds(60),
                                        expiresAt,
                                        scopes),
                                metadata -> metadata.put(
                                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                        invalidated))
                        .refreshToken(
                                new OAuth2RefreshToken(
                                        "initial-refresh",
                                        Instant.now(),
                                        Instant.now().plusSeconds(600)))
                        .build());
    }

    private int clientCount() throws Exception {
        try (var connection = this.dataSource.getConnection();
                var statement = connection.createStatement();
                var result = statement.executeQuery("select count(*) from oauth2_registered_client")) {
            result.next();
            return result.getInt(1);
        }
    }

    private static OidcClientRegistration.Builder metadata() {
        return OidcClientRegistration.builder()
                .redirectUri("https://rp.example/callback")
                .scope("openid");
    }

    private static OidcClientRegistrationRequest request() {
        return new OidcClientRegistrationRequest(
                identity("bootstrap", "initial"), metadata().build());
    }

    private static OidcClientConfigurationRequest read(OidcClientRegistration response) {
        return new OidcClientConfigurationRequest(
                identity(response.getClientId(), response.getRegistrationAccessToken()),
                response.getClientId());
    }

    private static SecurityIdentity identity(String name, String token) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(name))
                .addCredential(new TokenCredential(token, "bearer"))
                .build();
    }

    private static void assertError(String code, org.junit.jupiter.api.function.Executable action) {
        assertEquals(
                code,
                assertThrows(OAuth2AuthenticationException.class, action)
                        .getError()
                        .getErrorCode());
    }
}
