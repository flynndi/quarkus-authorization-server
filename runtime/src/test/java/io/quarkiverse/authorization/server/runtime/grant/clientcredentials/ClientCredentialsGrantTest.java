package io.quarkiverse.authorization.server.runtime.grant.clientcredentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequest;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestContext;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequestValidator;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class ClientCredentialsGrantTest {

    private static final Instant ISSUED_AT = Instant.parse("2026-09-03T01:00:00Z");
    private static final AuthorizationServerSettings SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example.com").build();

    private final RegisteredClient registeredClient = RegisteredClient.withId("machine-registration")
            .clientId("machine-client")
            .clientSecret("client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .scope("message.read")
            .scope("message.write")
            .scope(OidcScopes.OPENID)
            .clientSettings(
                    ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build();
    private final RecordingAuthorizationService authorizationService = new RecordingAuthorizationService();
    private final RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
    private final ClientCredentialsGrant provider = new ClientCredentialsGrant(
            this.authorizationService,
            this.tokenGenerator,
            new DefaultAuthorizationServerContext(SETTINGS),
            java.util.List.of(context -> {
            }),
            DPoPTestSupport.binding());

    @Test
    void issuesOnlyAccessTokenWithClientPrincipalAndPersistsClaims() {
        SecurityIdentity clientPrincipal = clientIdentity(this.registeredClient);
        Set<String> scopes = Set.of("message.read", OidcScopes.OPENID);
        ClientCredentialsRequest authentication = new ClientCredentialsRequest(
                clientPrincipal, scopes, Map.of("custom", "request-value"));

        TokenIssuanceResult result = this.provider.issueTokens(authentication);

        assertSame(clientPrincipal, result.getPrincipal());
        assertSame(this.registeredClient, result.getRegisteredClient());
        assertEquals(OAuth2AccessToken.TokenType.BEARER, result.getAccessToken().getTokenType());
        assertEquals("access-token", result.getAccessToken().getTokenValue());
        assertEquals(ISSUED_AT, result.getAccessToken().getIssuedAt());
        assertEquals(ISSUED_AT.plusSeconds(300), result.getAccessToken().getExpiresAt());
        assertEquals(scopes, result.getAccessToken().getScopes());
        assertNull(result.getRefreshToken());
        assertTrue(result.getAdditionalParameters().isEmpty());
        assertEquals(1, this.tokenGenerator.invocations);

        OAuth2TokenContext context = this.tokenGenerator.context;
        assertSame(this.registeredClient, context.getRegisteredClient());
        assertSame(clientPrincipal, context.getPrincipal());
        assertSame(authentication, context.getAuthorizationGrant());
        assertNull(context.getAuthorization());
        assertEquals(SETTINGS.getIssuer(), context.getAuthorizationServerContext().getIssuer());
        assertEquals(
                AuthorizationGrantType.CLIENT_CREDENTIALS, context.getAuthorizationGrantType());
        assertEquals(OAuth2TokenType.ACCESS_TOKEN, context.getTokenType());
        assertEquals(scopes, context.getAuthorizedScopes());

        OAuth2Authorization saved = this.authorizationService.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN);
        assertNotNull(saved);
        assertEquals(this.registeredClient.getId(), saved.getRegisteredClientId());
        assertEquals(this.registeredClient.getClientId(), saved.getPrincipalName());
        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, saved.getAuthorizationGrantType());
        assertEquals(scopes, saved.getAuthorizedScopes());
        assertSame(result.getAccessToken(), saved.getAccessToken().getToken());
        assertEquals(this.tokenGenerator.token.getClaims(), saved.getAccessToken().getClaims());
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED.getValue(),
                saved.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertFalse(saved.getAccessToken().isInvalidated());
        assertNull(saved.getRefreshToken());
        assertNull(saved.getToken(OidcIdToken.class));
        // Client-only authorization stores neither a resource-owner identity nor incoming client
        // credentials.
        assertTrue(saved.getAttributes().isEmpty());
        assertEquals(1, this.authorizationService.saveInvocations);
    }

    @Test
    void omittedScopesRemainEmptyEvenWhenClientHasScopes() {
        TokenIssuanceResult result = this.provider.issueTokens(authentication(null));

        assertTrue(result.getAccessToken().getScopes().isEmpty());
        assertTrue(this.tokenGenerator.context.getAuthorizedScopes().isEmpty());
        assertTrue(this.authorizationService.saved.getAuthorizedScopes().isEmpty());
        assertTrue(
                this.authorizationService.saved.getAccessToken().getToken().getScopes().isEmpty());
    }

    @Test
    void usesAuthorizedScopesInsteadOfScopesFromGeneratedClaims() {
        OAuth2TokenGenerator<OAuth2Token> generator = context -> new Jwt(
                "mapped-token",
                ISSUED_AT,
                ISSUED_AT.plusSeconds(300),
                Map.of("alg", "RS256"),
                Map.of(OAuth2ParameterNames.SCOPE, Set.of("mapped-scope")));

        TokenIssuanceResult result = provider(generator).issueTokens(authentication(Set.of("message.read")));

        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
        assertEquals(Set.of("message.read"), this.authorizationService.saved.getAuthorizedScopes());
        assertEquals(
                Set.of("mapped-scope"),
                this.authorizationService.saved
                        .getAccessToken()
                        .getClaims()
                        .get(OAuth2ParameterNames.SCOPE));
    }

    @Test
    void acceptsGeneratorWithoutClaims() {
        TokenIssuanceResult result = provider(
                context -> new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        "plain-token",
                        ISSUED_AT,
                        ISSUED_AT.plusSeconds(300)))
                .issueTokens(authentication(Set.of("message.read")));

        assertEquals("plain-token", result.getAccessToken().getTokenValue());
        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
        assertNull(this.authorizationService.saved.getAccessToken().getClaims());
    }

    @Test
    void rejectsAnonymousClientEvenWithRegisteredClientAttribute() {
        SecurityIdentity anonymous = QuarkusSecurityIdentity.builder()
                .setAnonymous(true)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        this.registeredClient)
                .build();

        assertError(
                new ClientCredentialsRequest(anonymous, Set.of(), Map.of()),
                OAuth2ErrorCodes.INVALID_CLIENT);
    }

    @Test
    void rejectsUserIdentityWithoutRegisteredClient() {
        SecurityIdentity resourceOwner = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                .build();

        assertError(
                new ClientCredentialsRequest(resourceOwner, Set.of(), Map.of()),
                OAuth2ErrorCodes.INVALID_CLIENT);
    }

    @Test
    void rejectsClientWithoutClientCredentialsGrantBeforeCallingValidator() {
        RegisteredClient otherClient = RegisteredClient.withId("other-registration")
                .clientId("other-client")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .build();
        var provider = providerWithValidator(
                context -> {
                    throw new AssertionError(
                            "Unauthorized client must not reach the validator");
                });

        assertError(
                provider,
                new ClientCredentialsRequest(clientIdentity(otherClient), Set.of(), Map.of()),
                OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    @Test
    void rejectsScopeOutsideRegisteredClient() {
        assertError(
                authentication(Set.of("message.read", "message.admin")),
                OAuth2ErrorCodes.INVALID_SCOPE);
    }

    @Test
    void customValidatorReceivesValidatedRequestAndClient() {
        AtomicReference<ClientCredentialsRequestContext> seen = new AtomicReference<>();
        var provider = providerWithValidator(seen::set);
        ClientCredentialsRequest authentication = authentication(Set.of("message.read"));

        TokenIssuanceResult result = provider.issueTokens(authentication);

        assertSame(authentication, seen.get().request());
        assertSame(this.registeredClient, seen.get().registeredClient());
        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
    }

    @Test
    void customValidatorCannotBypassMandatoryScopeValidation() {
        AtomicReference<ClientCredentialsRequestContext> seen = new AtomicReference<>();
        var provider = providerWithValidator(seen::set);

        assertError(
                provider, authentication(Set.of("message.admin")), OAuth2ErrorCodes.INVALID_SCOPE);
        assertNull(seen.get());
        provider.issueTokens(authentication(Set.of("message.read")));
        assertNotNull(seen.get());
    }

    @Test
    void customValidatorFailurePreventsGenerationAndSave() {
        var provider = providerWithValidator(
                context -> {
                    throw new OAuth2AuthenticationException(
                            OAuth2ErrorCodes.INVALID_REQUEST);
                });

        assertError(
                provider, authentication(Set.of("message.read")), OAuth2ErrorCodes.INVALID_REQUEST);
    }

    @Test
    void nullGeneratedTokenFailsWithoutSavingAuthorization() {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider(context -> null).issueTokens(authentication(Set.of())));

        assertEquals(OAuth2ErrorCodes.SERVER_ERROR, exception.getError().getErrorCode());
        assertEquals(
                "The token generator failed to generate the access token.",
                exception.getError().getDescription());
        assertEquals(
                "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
                exception.getError().getUri());
        assertEquals(0, this.authorizationService.saveInvocations);
    }

    @Test
    void generationFailureDoesNotSaveOrReturnSuccess() {
        IllegalStateException failure = new IllegalStateException("Signing failed");

        assertSame(
                failure,
                assertThrows(
                        IllegalStateException.class,
                        () -> provider(
                                context -> {
                                    throw failure;
                                })
                                .issueTokens(authentication(Set.of()))));
        assertEquals(0, this.authorizationService.saveInvocations);
    }

    @Test
    void invalidGeneratedTokenCannotBeConvertedAndSaved() {
        OAuth2Token invalidToken = new OAuth2Token() {
            @Override
            public String getTokenValue() {
                return "";
            }

            @Override
            public Instant getIssuedAt() {
                return ISSUED_AT;
            }

            @Override
            public Instant getExpiresAt() {
                return ISSUED_AT.plusSeconds(300);
            }
        };

        assertThrows(
                IllegalArgumentException.class,
                () -> provider(context -> invalidToken).issueTokens(authentication(Set.of())));
        assertEquals(0, this.authorizationService.saveInvocations);
    }

    @Test
    void saveFailureDoesNotReturnSuccess() {
        this.authorizationService.failure = new IllegalStateException("Save failed");

        assertSame(
                this.authorizationService.failure,
                assertThrows(
                        IllegalStateException.class,
                        () -> this.provider.issueTokens(authentication(Set.of()))));
        assertEquals(1, this.tokenGenerator.invocations);
        assertEquals(1, this.authorizationService.saveInvocations);
        assertNull(
                this.authorizationService.findByToken(
                        "access-token", OAuth2TokenType.ACCESS_TOKEN));
    }

    @Test
    void requiresDependenciesAndValidator() {
        assertThrows(
                NullPointerException.class,
                () -> new ClientCredentialsGrant(
                        null,
                        this.tokenGenerator,
                        new DefaultAuthorizationServerContext(SETTINGS),
                        java.util.List.of(context -> {
                        }),
                        DPoPTestSupport.binding()));
        assertThrows(
                NullPointerException.class,
                () -> new ClientCredentialsGrant(
                        this.authorizationService,
                        null,
                        new DefaultAuthorizationServerContext(SETTINGS),
                        java.util.List.of(context -> {
                        }),
                        DPoPTestSupport.binding()));
        assertThrows(
                NullPointerException.class,
                () -> new ClientCredentialsGrant(
                        this.authorizationService,
                        this.tokenGenerator,
                        null,
                        java.util.List.of(context -> {
                        }),
                        DPoPTestSupport.binding()));
        assertThrows(NullPointerException.class, () -> providerWithValidator(null));
    }

    private void assertError(ClientCredentialsRequest authentication, String errorCode) {
        assertError(this.provider, authentication, errorCode);
    }

    private void assertError(
            ClientCredentialsGrant provider,
            ClientCredentialsRequest authentication,
            String errorCode) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.issueTokens(authentication));
        assertEquals(errorCode, exception.getError().getErrorCode());
        assertEquals(0, this.tokenGenerator.invocations);
        assertEquals(0, this.authorizationService.saveInvocations);
    }

    private ClientCredentialsGrant provider(OAuth2TokenGenerator<? extends OAuth2Token> generator) {
        return new ClientCredentialsGrant(
                this.authorizationService,
                generator,
                new DefaultAuthorizationServerContext(SETTINGS),
                java.util.List.of(context -> {
                }),
                DPoPTestSupport.binding());
    }

    private ClientCredentialsGrant providerWithValidator(
            ClientCredentialsRequestValidator validator) {
        return new ClientCredentialsGrant(
                this.authorizationService,
                this.tokenGenerator,
                new DefaultAuthorizationServerContext(SETTINGS),
                java.util.List.of(validator),
                DPoPTestSupport.binding());
    }

    private ClientCredentialsRequest authentication(Set<String> scopes) {
        return new ClientCredentialsRequest(
                clientIdentity(this.registeredClient), scopes, Map.of());
    }

    private static SecurityIdentity clientIdentity(RegisteredClient registeredClient) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        registeredClient)
                .addAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .addAttribute("unrelated-runtime-attribute", new Object())
                .build();
    }

    private static final class RecordingTokenGenerator
            implements OAuth2TokenGenerator<OAuth2Token> {

        private OAuth2TokenContext context;
        private Jwt token;
        private int invocations;

        @Override
        public OAuth2Token generate(OAuth2TokenContext context) {
            this.context = context;
            this.invocations++;
            assertEquals(OAuth2TokenType.ACCESS_TOKEN, context.getTokenType());
            this.token = new Jwt(
                    "access-token",
                    ISSUED_AT,
                    ISSUED_AT.plusSeconds(300),
                    Map.of("alg", "RS256"),
                    Map.of(
                            "sub",
                            context.getPrincipal().getPrincipal().getName(),
                            "aud",
                            List.of(context.getRegisteredClient().getClientId()),
                            "iat",
                            ISSUED_AT,
                            "exp",
                            ISSUED_AT.plusSeconds(300),
                            OAuth2ParameterNames.SCOPE,
                            context.getAuthorizedScopes()));
            return this.token;
        }
    }

    private static final class RecordingAuthorizationService implements OAuth2AuthorizationService {

        private final InMemoryOAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
        private OAuth2Authorization saved;
        private int saveInvocations;
        private RuntimeException failure;

        @Override
        public void save(OAuth2Authorization authorization) {
            this.saveInvocations++;
            if (this.failure != null) {
                throw this.failure;
            }
            this.saved = authorization;
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
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            return this.delegate.findByToken(token, tokenType);
        }
    }
}
