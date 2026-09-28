package io.quarkiverse.authorization.server.runtime.grant.refreshtoken;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.grant.refreshtoken.RefreshTokenRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
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

class RefreshTokenGrantTest {

    @Test
    void publicRefreshCannotAdoptAnUnboundPersistedToken() {
        var client = RegisteredClient.withId("public-registration")
                .clientId("public-client")
                .clientAuthenticationMethod(
                        io.quarkiverse.authorization.server.model.ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .build();
        var original = OAuth2Authorization.from(
                authorization(
                        client,
                        "refresh-token",
                        Instant.now().plusSeconds(300),
                        false))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();
        var service = new InMemoryOAuth2AuthorizationService(original);
        var principal = QuarkusSecurityIdentity.builder(clientIdentity(client))
                .addAttribute(
                        OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        io.quarkiverse.authorization.server.model.ClientAuthenticationMethod.NONE)
                .build();
        var error = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider(
                        service,
                        context -> {
                            throw new AssertionError(
                                    "Must reject before issuance");
                        })
                        .issueTokens(
                                authentication(
                                        "refresh-token", principal, Set.of())));
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getError().getErrorCode());
        assertSame(original, service.findById(original.getId()));
    }

    @Test
    void exchangesRefreshTokenAndPersistsActiveAccessToken() {
        RegisteredClient registeredClient = registeredClient("messaging-client", true);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "refresh-token",
                        Instant.now().plusSeconds(3600),
                        false));
        RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
        RefreshTokenGrant provider = provider(authorizationService, tokenGenerator);
        SecurityIdentity clientPrincipal = clientIdentity(registeredClient);

        TokenIssuanceResult result = provider.issueTokens(authentication("refresh-token", clientPrincipal, Set.of()));

        assertSame(clientPrincipal, result.getPrincipal());
        assertEquals("refresh-token", result.getRefreshToken().getTokenValue());
        assertEquals(Set.of("message.read", "message.write"), result.getAccessToken().getScopes());
        assertEquals(
                AuthorizationGrantType.REFRESH_TOKEN,
                tokenGenerator.context.getAuthorizationGrantType());
        assertEquals(
                "resource-owner", tokenGenerator.context.getPrincipal().getPrincipal().getName());
        assertEquals(0, tokenGenerator.refreshTokenInvocations);

        OAuth2Authorization restored = authorizationService.findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN);
        assertEquals(result.getAccessToken(), restored.getAccessToken().getToken());
        assertEquals(
                OAuth2TokenFormat.SELF_CONTAINED.getValue(),
                restored.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertFalse(restored.getAccessToken().isInvalidated());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void replacesIssuedFormatWhenRefreshingAfterClientFormatChange(boolean wasJwt) {
        OAuth2TokenFormat oldFormat = wasJwt ? OAuth2TokenFormat.SELF_CONTAINED : OAuth2TokenFormat.REFERENCE;
        OAuth2TokenFormat newFormat = wasJwt ? OAuth2TokenFormat.REFERENCE : OAuth2TokenFormat.SELF_CONTAINED;
        RegisteredClient currentClient = RegisteredClient.from(registeredClient("messaging-client", true))
                .tokenSettings(TokenSettings.builder().accessTokenFormat(newFormat).build())
                .build();
        OAuth2Authorization old = authorization(
                currentClient, "refresh-token", Instant.now().plusSeconds(3600), false);
        old = OAuth2Authorization.from(old)
                .token(
                        old.getAccessToken().getToken(),
                        metadata -> {
                            metadata.put(
                                    OAuth2TokenFormat.class.getName(),
                                    oldFormat.getValue());
                            metadata.put(
                                    OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                    Map.of("old-claim", "old-value"));
                        })
                .build();
        InMemoryOAuth2AuthorizationService service = new InMemoryOAuth2AuthorizationService(old);

        TokenIssuanceResult result = provider(service, new RecordingTokenGenerator())
                .issueTokens(
                        authentication(
                                "refresh-token", clientIdentity(currentClient), Set.of()));

        OAuth2Authorization restored = service.findByToken(
                result.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        assertEquals(
                newFormat.getValue(),
                restored.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        assertFalse(restored.getAccessToken().isInvalidated());
        assertNull(restored.getAccessToken().getClaims());
        assertEquals(
                oldFormat.getValue(),
                old.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
    }

    @Test
    void rotatesRefreshTokenWhenReuseIsDisabled() {
        RegisteredClient registeredClient = registeredClient("messaging-client", true, false);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "refresh-token",
                        Instant.now().plusSeconds(3600),
                        false));
        RecordingTokenGenerator tokenGenerator = new RecordingTokenGenerator();
        RefreshTokenGrant provider = provider(authorizationService, tokenGenerator);
        SecurityIdentity clientPrincipal = clientIdentity(registeredClient);

        TokenIssuanceResult result = provider.issueTokens(authentication("refresh-token", clientPrincipal, Set.of()));

        assertEquals("rotated-refresh-token", result.getRefreshToken().getTokenValue());
        assertEquals(1, tokenGenerator.refreshTokenInvocations);
        assertNull(
                authorizationService.findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN));
        OAuth2Authorization restored = authorizationService.findByToken(
                "rotated-refresh-token", OAuth2TokenType.REFRESH_TOKEN);
        assertNotNull(restored);
        assertEquals(result.getRefreshToken(), restored.getRefreshToken().getToken());
        assertEquals(result.getAccessToken(), restored.getAccessToken().getToken());

        assertError(
                provider,
                authentication("refresh-token", clientPrincipal, Set.of()),
                OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    void doesNotSaveAccessTokenWhenRefreshTokenGenerationFails() {
        RegisteredClient registeredClient = registeredClient("messaging-client", true, false);
        OAuth2Authorization originalAuthorization = authorization(
                registeredClient, "refresh-token", Instant.now().plusSeconds(3600), false);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(originalAuthorization);
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
        RefreshTokenGrant provider = provider(authorizationService, tokenGenerator);

        assertError(
                provider,
                authentication("refresh-token", clientIdentity(registeredClient), Set.of()),
                OAuth2ErrorCodes.SERVER_ERROR);

        assertEquals(
                originalAuthorization,
                authorizationService.findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN));
    }

    @Test
    void narrowsAccessTokenScopes() {
        RegisteredClient registeredClient = registeredClient("messaging-client", true);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "refresh-token",
                        Instant.now().plusSeconds(3600),
                        false));
        RefreshTokenGrant provider = provider(authorizationService, new RecordingTokenGenerator());

        TokenIssuanceResult result = provider.issueTokens(
                authentication(
                        "refresh-token",
                        clientIdentity(registeredClient),
                        Set.of("message.read")));

        assertEquals(Set.of("message.read"), result.getAccessToken().getScopes());
    }

    @Test
    void rejectsUnknownExpiredAndInvalidatedRefreshToken() {
        RegisteredClient registeredClient = registeredClient("messaging-client", true);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "expired-token",
                        Instant.now().minusSeconds(1),
                        false),
                authorization(
                        registeredClient,
                        "invalidated-token",
                        Instant.now().plusSeconds(3600),
                        true));
        RefreshTokenGrant provider = provider(authorizationService, new RecordingTokenGenerator());
        SecurityIdentity clientPrincipal = clientIdentity(registeredClient);

        assertError(
                provider,
                authentication("unknown-token", clientPrincipal, Set.of()),
                OAuth2ErrorCodes.INVALID_GRANT);
        assertError(
                provider,
                authentication("expired-token", clientPrincipal, Set.of()),
                OAuth2ErrorCodes.INVALID_GRANT);
        assertError(
                provider,
                authentication("invalidated-token", clientPrincipal, Set.of()),
                OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    void rejectsRefreshTokenIssuedToAnotherClient() {
        RegisteredClient registeredClient = registeredClient("messaging-client", true);
        RegisteredClient anotherClient = registeredClient("another-client", true);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "refresh-token",
                        Instant.now().plusSeconds(3600),
                        false));
        RefreshTokenGrant provider = provider(authorizationService, new RecordingTokenGenerator());

        assertError(
                provider,
                authentication("refresh-token", clientIdentity(anotherClient), Set.of()),
                OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Test
    void rejectsClientWithoutRefreshTokenGrant() {
        RegisteredClient issuedClient = registeredClient("messaging-client", true);
        RegisteredClient configuredClient = registeredClient("messaging-client", false);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        issuedClient,
                        "refresh-token",
                        Instant.now().plusSeconds(3600),
                        false));
        RefreshTokenGrant provider = provider(authorizationService, new RecordingTokenGenerator());

        assertError(
                provider,
                authentication("refresh-token", clientIdentity(configuredClient), Set.of()),
                OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    @Test
    void rejectsScopeOutsideOriginalAuthorization() {
        RegisteredClient registeredClient = registeredClient("messaging-client", true);
        InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
                authorization(
                        registeredClient,
                        "refresh-token",
                        Instant.now().plusSeconds(3600),
                        false));
        RefreshTokenGrant provider = provider(authorizationService, new RecordingTokenGenerator());

        assertError(
                provider,
                authentication(
                        "refresh-token",
                        clientIdentity(registeredClient),
                        Set.of("messages.admin")),
                OAuth2ErrorCodes.INVALID_SCOPE);
    }

    private static void assertError(
            RefreshTokenGrant provider, RefreshTokenRequest authentication, String errorCode) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> provider.issueTokens(authentication));
        assertEquals(errorCode, exception.getError().getErrorCode());
    }

    private static RefreshTokenGrant provider(
            InMemoryOAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        return new RefreshTokenGrant(
                authorizationService,
                tokenGenerator,
                new DefaultAuthorizationServerContext(
                        AuthorizationServerSettings.builder().issuer("https://issuer.example.com").build()),
                io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport.binding());
    }

    private static OAuth2Authorization authorization(
            RegisteredClient registeredClient,
            String tokenValue,
            Instant expiresAt,
            boolean invalidated) {
        Instant issuedAt = expiresAt.minusSeconds(3600);
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt);
        OAuth2AccessToken oldAccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "old-access-token-" + tokenValue,
                issuedAt,
                issuedAt.plusSeconds(300),
                Set.of("message.read", "message.write"));
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(Set.of("message.read", "message.write"))
                .attribute(SecurityIdentity.class.getName(), identity("resource-owner"))
                .token(
                        oldAccessToken,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
                .token(
                        refreshToken,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                invalidated))
                .build();
    }

    private static RefreshTokenRequest authentication(
            String refreshToken, SecurityIdentity clientPrincipal, Set<String> scopes) {
        return new RefreshTokenRequest(refreshToken, clientPrincipal, scopes, Map.of());
    }

    private static RegisteredClient registeredClient(String clientId, boolean refreshTokenGrant) {
        return registeredClient(clientId, refreshTokenGrant, true);
    }

    private static RegisteredClient registeredClient(
            String clientId, boolean refreshTokenGrant, boolean reuseRefreshTokens) {
        RegisteredClient.Builder builder = RegisteredClient.withId(clientId + "-registration")
                .clientId(clientId)
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("message.read")
                .scope("message.write")
                .tokenSettings(
                        TokenSettings.builder()
                                .reuseRefreshTokens(reuseRefreshTokens)
                                .build());
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
        private int refreshTokenInvocations;

        @Override
        public OAuth2Token generate(OAuth2TokenContext context) {
            this.context = context;
            Instant issuedAt = Instant.now();
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                this.refreshTokenInvocations++;
                return new OAuth2RefreshToken(
                        "rotated-refresh-token", issuedAt, issuedAt.plusSeconds(3600));
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
