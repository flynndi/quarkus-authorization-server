package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.exchange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class AuthorizationCodeExchangeTest {

    @Test
    void customGeneratorCannotIssueAnUnboundRefreshTokenToAPublicClient() {
        var client = RegisteredClient.withId("public-registration")
                .clientId("public-client")
                .clientAuthenticationMethod(
                        io.quarkiverse.authorization.server.model.ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .build();
        var original = authorization(client, "code", Instant.now().plusSeconds(300));
        var service = new InMemoryOAuth2AuthorizationService(original);
        var principal = QuarkusSecurityIdentity.builder(clientIdentity(client))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        io.quarkiverse.authorization.server.model.ClientAuthenticationMethod.NONE)
                .build();
        var error = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider(service, new RecordingTokenGenerator())
                        .exchange(
                                authentication(
                                        "code",
                                        principal,
                                        "https://client.example.com/callback")));
        assertEquals(OAuth2ErrorCodes.SERVER_ERROR, error.getError().getErrorCode());
        assertSame(original, service.findById(original.getId()));
        assertTrue(original.getAuthorizationCode().isActive());
        assertNull(original.getAccessToken());
        assertNull(original.getRefreshToken());
    }

    @Test
    void exchangesAuthorizationCodeAndPersistsAccessToken() {
        RegisteredClient registeredClient = registeredClient("messaging-client");
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "authorization-code",
                        Instant.now().plusSeconds(300)));
        RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
        AuthorizationCodeExchange provider = provider(authorizationService, tokenGenerator);
        SecurityIdentity clientPrincipal = clientIdentity(registeredClient);

        TokenIssuanceResult result = provider.exchange(
                authentication(
                        "authorization-code",
                        clientPrincipal,
                        "https://client.example.com/callback"));

        assertSame(clientPrincipal, result.getPrincipal());
        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
        assertEquals(
                AuthorizationGrantType.AUTHORIZATION_CODE,
                tokenGenerator.context.getAuthorizationGrantType());
        assertEquals(
                "resource-owner", tokenGenerator.context.getPrincipal().getPrincipal().getName());
        assertEquals(Set.of("message.read"), tokenGenerator.context.getAuthorizedScopes());

        OAuth2Authorization restored = authorizationService.findByToken("authorization-code", new OAuth2TokenType("code"));
        assertNotNull(restored.getAccessToken());
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED.getValue(),
                restored.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertEquals(result.getAccessToken(), restored.getAccessToken().getToken());
        assertTrue(restored.getAuthorizationCode().isInvalidated());
    }

    @Test
    void issuesAndPersistsRefreshTokenWhenClientDeclaresRefreshTokenGrant() {
        RegisteredClient registeredClient = registeredClient("messaging-client", true);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "authorization-code",
                        Instant.now().plusSeconds(300)));
        RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
        AuthorizationCodeExchange provider = provider(authorizationService, tokenGenerator);

        TokenIssuanceResult result = provider.exchange(
                authentication(
                        "authorization-code",
                        clientIdentity(registeredClient),
                        "https://client.example.com/callback"));

        assertNotNull(result.getRefreshToken());
        assertEquals(2, tokenGenerator.invocations);
        OAuth2Authorization restored = authorizationService.findByToken(
                result.getRefreshToken().getTokenValue(), OAuth2TokenType.REFRESH_TOKEN);
        assertNotNull(restored);
        assertEquals(result.getRefreshToken(), restored.getRefreshToken().getToken());
        assertTrue(restored.getAuthorizationCode().isInvalidated());
    }

    @Test
    void doesNotGenerateRefreshTokenWhenClientDoesNotDeclareRefreshTokenGrant() {
        RegisteredClient registeredClient = registeredClient("messaging-client");
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "authorization-code",
                        Instant.now().plusSeconds(300)));
        RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
        AuthorizationCodeExchange provider = provider(authorizationService, tokenGenerator);

        TokenIssuanceResult result = provider.exchange(
                authentication(
                        "authorization-code",
                        clientIdentity(registeredClient),
                        "https://client.example.com/callback"));

        assertNull(result.getRefreshToken());
        assertEquals(1, tokenGenerator.invocations);
    }

    @Test
    void acceptsMissingGeneratedRefreshTokenForAuthorizationCodeGrant() {
        RegisteredClient registeredClient = registeredClient("public-client", true);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "authorization-code",
                        Instant.now().plusSeconds(300)));
        OAuth2TokenGenerator<OAuth2Token> tokenGenerator = context -> {
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            return new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "access-token",
                    issuedAt,
                    issuedAt.plusSeconds(300),
                    context.getAuthorizedScopes());
        };
        AuthorizationCodeExchange provider = provider(authorizationService, tokenGenerator);

        TokenIssuanceResult result = provider.exchange(
                authentication(
                        "authorization-code",
                        clientIdentity(registeredClient),
                        "https://client.example.com/callback"));

        assertNull(result.getRefreshToken());
        OAuth2Authorization restored = authorizationService.findByToken("authorization-code", new OAuth2TokenType("code"));
        assertNotNull(restored.getAccessToken());
        assertTrue(restored.getAuthorizationCode().isInvalidated());
    }

    @Test
    void rejectsRedirectUriMismatchWithoutConsumingCode() {
        RegisteredClient registeredClient = registeredClient("messaging-client");
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "authorization-code",
                        Instant.now().plusSeconds(300)));
        AuthorizationCodeExchange provider = provider(authorizationService, new RecordingTokenGenerator());

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.exchange(
                        authentication(
                                "authorization-code",
                                clientIdentity(registeredClient),
                                "https://client.example.com/other")));

        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, exception.getError().getErrorCode());
        assertFalse(
                authorizationService
                        .findByToken("authorization-code", new OAuth2TokenType("code"))
                        .getAuthorizationCode()
                        .isInvalidated());
    }

    @Test
    void invalidatesCodeUsedByAnotherClient() {
        RegisteredClient registeredClient = registeredClient("messaging-client");
        RegisteredClient anotherClient = registeredClient("another-client");
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "authorization-code",
                        Instant.now().plusSeconds(300)));
        AuthorizationCodeExchange provider = provider(authorizationService, new RecordingTokenGenerator());

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.exchange(
                        authentication(
                                "authorization-code",
                                clientIdentity(anotherClient),
                                "https://client.example.com/callback")));

        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, exception.getError().getErrorCode());
        assertTrue(
                authorizationService
                        .findByToken("authorization-code", new OAuth2TokenType("code"))
                        .getAuthorizationCode()
                        .isInvalidated());
    }

    @Test
    void rejectsExpiredCode() {
        RegisteredClient registeredClient = registeredClient("messaging-client");
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient, "expired-code", Instant.now().minusSeconds(1)));
        AuthorizationCodeExchange provider = provider(authorizationService, new RecordingTokenGenerator());

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.exchange(
                        authentication(
                                "expired-code",
                                clientIdentity(registeredClient),
                                "https://client.example.com/callback")));

        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, exception.getError().getErrorCode());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void rejectsCodeReplayAndInvalidatesPreviouslyIssuedTokens(boolean withRefreshToken) {
        RegisteredClient registeredClient = registeredClient("messaging-client", withRefreshToken);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "authorization-code",
                        Instant.now().plusSeconds(300)));
        AuthorizationCodeExchange provider = provider(authorizationService, new RecordingTokenGenerator());
        AuthorizationCodeExchangeRequest authentication = authentication(
                "authorization-code",
                clientIdentity(registeredClient),
                "https://client.example.com/callback");
        provider.exchange(authentication);

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.exchange(authentication));

        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, exception.getError().getErrorCode());
        OAuth2Authorization restored = authorizationService.findByToken("authorization-code", new OAuth2TokenType("code"));
        assertTrue(restored.getAuthorizationCode().isInvalidated());
        assertTrue(restored.getAccessToken().isInvalidated());
        if (withRefreshToken) {
            assertTrue(restored.getRefreshToken().isInvalidated());
        } else {
            assertNull(restored.getRefreshToken());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void generationFailureDoesNotConsumeCodeOrSavePartialTokens(boolean failAccessToken) {
        RegisteredClient client = registeredClient("messaging-client", true);
        OAuth2Authorization original = authorization(client, "code", Instant.now().plusSeconds(300));
        InMemoryOAuth2AuthorizationService service = new InMemoryOAuth2AuthorizationService(original);
        RecordingTokenGenerator generator = new RecordingTokenGenerator();
        AuthorizationCodeExchange provider = provider(
                service,
                context -> {
                    if (failAccessToken) {
                        return null;
                    }
                    if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                        Instant issuedAt = Instant.now();
                        return new OAuth2AuthorizationCode(
                                "wrong-token-type", issuedAt, issuedAt.plusSeconds(300));
                    }
                    return generator.generate(context);
                });

        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.exchange(
                        authentication(
                                "code",
                                clientIdentity(client),
                                "https://client.example.com/callback")));

        assertEquals(OAuth2ErrorCodes.SERVER_ERROR, exception.getError().getErrorCode());
        assertSame(original, service.findById(original.getId()));
        assertTrue(original.getAuthorizationCode().isActive());
        assertNull(service.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN));
    }

    @Test
    void saveFailureDoesNotReturnTokensOrMutateOriginalCode() {
        RegisteredClient client = registeredClient("messaging-client", true);
        OAuth2Authorization original = authorization(client, "code", Instant.now().plusSeconds(300));
        IllegalStateException failure = new IllegalStateException("save failed");
        OAuth2AuthorizationService service = new OAuth2AuthorizationService() {
            @Override
            public void save(OAuth2Authorization authorization) {
                assertTrue(authorization.getAuthorizationCode().isInvalidated());
                assertNotNull(authorization.getAccessToken());
                assertNotNull(authorization.getRefreshToken());
                throw failure;
            }

            @Override
            public void remove(OAuth2Authorization authorization) {
                throw new AssertionError("Unexpected remove");
            }

            @Override
            public OAuth2Authorization findById(String id) {
                return original;
            }

            @Override
            public OAuth2Authorization findByToken(String token, OAuth2TokenType type) {
                return original;
            }
        };
        AuthorizationCodeExchange provider = provider(service, new RecordingTokenGenerator());

        assertSame(
                failure,
                assertThrows(
                        IllegalStateException.class,
                        () -> provider.exchange(
                                authentication(
                                        "code",
                                        clientIdentity(client),
                                        "https://client.example.com/callback"))));
        assertTrue(original.getAuthorizationCode().isActive());
        assertNull(original.getAccessToken());
        assertNull(original.getRefreshToken());
    }

    private static AuthorizationCodeExchange provider(
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        return new AuthorizationCodeExchange(
                authorizationService,
                tokenGenerator,
                new DefaultAuthorizationServerContext(
                        AuthorizationServerSettings.builder().issuer("https://issuer.example.com").build()),
                io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport.binding());
    }

    private static OAuth2Authorization authorization(
            RegisteredClient registeredClient, String code, Instant expiresAt) {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://issuer.example.com/oauth2/authorize")
                .clientId(registeredClient.getClientId())
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .state("state")
                .additionalParameters(Map.of("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "code_challenge_method", "S256"))
                .build();
        Instant issuedAt = expiresAt.minusSeconds(300);
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("message.read"))
                .attribute(SecurityIdentity.class.getName(), identity("resource-owner"))
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .authorizationCode(new OAuth2AuthorizationCode(code, issuedAt, expiresAt))
                .build();
    }

    private static AuthorizationCodeExchangeRequest authentication(
            String code, SecurityIdentity clientPrincipal, String redirectUri) {
        return new AuthorizationCodeExchangeRequest(
                code,
                clientPrincipal,
                redirectUri,
                Map.of("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    }

    private static RegisteredClient registeredClient(String clientId) {
        return registeredClient(clientId, false);
    }

    private static RegisteredClient registeredClient(String clientId, boolean refreshTokenGrant) {
        RegisteredClient.Builder builder = RegisteredClient.withId(clientId + "-registration")
                .clientId(clientId)
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read");
        if (refreshTokenGrant) {
            builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        }
        return builder.build();
    }

    private static SecurityIdentity clientIdentity(RegisteredClient registeredClient) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE,
                        registeredClient)
                .build();
    }

    private static SecurityIdentity identity(String principalName) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(principalName))
                .build();
    }

    private static final class RecordingTokenGenerator
            implements OAuth2TokenGenerator<OAuth2Token> {

        private OAuth2TokenContext context;
        private int invocations;

        @Override
        public OAuth2Token generate(OAuth2TokenContext context) {
            this.context = context;
            this.invocations++;
            Instant issuedAt = Instant.now();
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return new OAuth2RefreshToken(
                        "refresh-token", issuedAt, issuedAt.plusSeconds(3600));
            }
            return new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "access-token",
                    issuedAt,
                    issuedAt.plusSeconds(300),
                    context.getAuthorizedScopes());
        }
    }
}
