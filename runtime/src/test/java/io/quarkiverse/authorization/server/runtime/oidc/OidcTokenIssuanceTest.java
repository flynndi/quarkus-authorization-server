package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
import io.quarkiverse.authorization.server.grant.refreshtoken.RefreshTokenRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.exchange.AuthorizationCodeExchange;
import io.quarkiverse.authorization.server.runtime.grant.refreshtoken.RefreshTokenGrant;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.Jwt;
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

class OidcTokenIssuanceTest {

    private static final AuthorizationServerSettings SETTINGS = AuthorizationServerSettings.builder()
            .issuer("https://issuer.example").build();
    private static final RegisteredClient CLIENT = RegisteredClient.withId("registration")
            .clientId("client")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("https://client.example/callback")
            .scope("openid")
            .scope("message.read")
            // These tests isolate token generation failures from PKCE validation.
            .clientSettings(io.quarkiverse.authorization.server.settings.ClientSettings.builder().requireProofKey(false)
                    .build())
            .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build())
            .build();
    private static final SecurityIdentity CLIENT_IDENTITY = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("client"))
            .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, CLIENT).build();

    @Test
    void invalidIdTokenGeneratorResultsDoNotConsumeCodeOrSavePartialTokens() {
        for (boolean wrongType : List.of(false, true)) {
            OAuth2Authorization original = authorization();
            InMemoryOAuth2AuthorizationService service = new InMemoryOAuth2AuthorizationService(original);
            OAuth2TokenGenerator<OAuth2Token> generator = context -> {
                OAuth2Token token = accessOrRefresh(context);
                if (token != null) {
                    return token;
                }
                assertNotNull(context.getAuthorization().getAccessToken());
                assertNotNull(context.getAuthorization().getRefreshToken());
                return wrongType
                        ? new OAuth2RefreshToken("wrong-id-token", Instant.now(), null)
                        : null;
            };
            AuthorizationCodeExchange provider = new AuthorizationCodeExchange(
                    service,
                    generator,
                    new DefaultAuthorizationServerContext(SETTINGS),
                    io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport
                            .binding());
            OAuth2AuthenticationException error = assertThrows(OAuth2AuthenticationException.class,
                    () -> provider.exchange(codeRequest()));
            assertEquals("server_error", error.getError().getErrorCode());
            assertSame(original, service.findById(original.getId()));
            assertTrue(original.getAuthorizationCode().isActive());
        }
    }

    @Test
    void failedIdTokenRefreshDoesNotRotateOrOverwriteExistingTokens() {
        OAuth2Authorization original = authorization();
        InMemoryOAuth2AuthorizationService service = new InMemoryOAuth2AuthorizationService(original);
        RefreshTokenGrant provider = new RefreshTokenGrant(
                service,
                OidcTokenIssuanceTest::accessOrRefresh,
                new DefaultAuthorizationServerContext(SETTINGS),
                io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport.binding());
        OAuth2AuthenticationException error = assertThrows(OAuth2AuthenticationException.class,
                () -> provider.issueTokens(new RefreshTokenRequest(
                        "old-refresh", CLIENT_IDENTITY, Set.of("message.read"), Map.of())));
        assertEquals("server_error", error.getError().getErrorCode());
        assertSame(original, service.findByToken("old-refresh", OAuth2TokenType.REFRESH_TOKEN));
        assertNull(service.findByToken("new-refresh", OAuth2TokenType.REFRESH_TOKEN));
        assertNull(service.findByToken("new-access", OAuth2TokenType.ACCESS_TOKEN));
    }

    @Test
    void idTokenContextContainsNewTokensAndOriginalAuthorizationWhenRefreshingWithNarrowerScopes() {
        OAuth2Authorization original = authorization();
        InMemoryOAuth2AuthorizationService service = new InMemoryOAuth2AuthorizationService(original);
        AtomicInteger idTokenCalls = new AtomicInteger();
        OAuth2TokenGenerator<OAuth2Token> generator = context -> {
            OAuth2Token token = accessOrRefresh(context);
            if (token != null) {
                return token;
            }
            idTokenCalls.incrementAndGet();
            assertEquals(
                    "new-access",
                    context.getAuthorization().getAccessToken().getToken().getTokenValue());
            assertEquals(
                    "new-refresh",
                    context.getAuthorization()
                            .getRefreshToken()
                            .getToken()
                            .getTokenValue());
            assertEquals(Set.of("message.read"), context.getAuthorizedScopes());
            assertEquals(
                    Set.of("openid", "message.read"),
                    context.getAuthorization().getAuthorizedScopes());
            assertNotNull(context.getAuthorization().getToken(OidcIdToken.class));
            Instant now = Instant.now();
            return new Jwt(
                    "new-id-token",
                    now,
                    now.plusSeconds(1800),
                    Map.of("alg", "RS256"),
                    Map.of("sub", "alice"));
        };
        TokenIssuanceResult result = new RefreshTokenGrant(
                service,
                generator,
                new DefaultAuthorizationServerContext(SETTINGS),
                io.quarkiverse.authorization.server.runtime.dpop.DPoPTestSupport
                        .binding())
                .issueTokens(
                        new RefreshTokenRequest(
                                "old-refresh",
                                CLIENT_IDENTITY,
                                Set.of("message.read"),
                                Map.of()));
        assertEquals(1, idTokenCalls.get());
        assertEquals("new-id-token", result.getAdditionalParameters().get("id_token"));
        assertNotNull(service.findByToken("new-id-token", new OAuth2TokenType("id_token")));
        assertNull(service.findByToken("old-id-token", null));
    }

    private static OAuth2Token accessOrRefresh(OAuth2TokenContext context) {
        Instant now = Instant.now();
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "new-access", now,
                    now.plusSeconds(300), context.getAuthorizedScopes());
        }
        if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return new OAuth2RefreshToken("new-refresh", now, now.plusSeconds(3600));
        }
        return null;
    }

    private static AuthorizationCodeExchangeRequest codeRequest() {
        return new AuthorizationCodeExchangeRequest("code", CLIENT_IDENTITY,
                "https://client.example/callback", Map.of());
    }

    private static OAuth2Authorization authorization() {
        Instant now = Instant.now();
        OidcIdToken idToken = new OidcIdToken("old-id-token", now, now.plusSeconds(1800), Map.of("sub", "alice"));
        return OAuth2Authorization.withRegisteredClient(CLIENT)
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("openid", "message.read"))
                .attribute(
                        SecurityIdentity.class.getName(),
                        QuarkusSecurityIdentity.builder()
                                .setPrincipal(new QuarkusPrincipal("alice"))
                                .build())
                .attribute(
                        OAuth2AuthorizationRequest.class.getName(),
                        OAuth2AuthorizationRequest.authorizationCode()
                                .authorizationUri("https://issuer.example/authorize")
                                .clientId("client")
                                .redirectUri("https://client.example/callback")
                                .scopes(Set.of("openid", "message.read"))
                                .build())
                .token(new OAuth2AuthorizationCode("code", now, now.plusSeconds(300)))
                .refreshToken(new OAuth2RefreshToken("old-refresh", now, now.plusSeconds(3600)))
                .token(
                        idToken,
                        metadata -> metadata.put(
                                OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                idToken.getClaims()))
                .build();
    }
}
