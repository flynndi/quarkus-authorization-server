package io.quarkiverse.authorization.server.runtime.introspection.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2TokenIntrospection;
import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OAuth2TokenIntrospectionAuthenticationProviderTest {

    private static final Instant ISSUED_AT = Instant.now().minusSeconds(60);

    private final RegisteredClient authorizedClient = RegisteredClient.withId("authorized-registration")
            .clientId("authorized-client")
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .build();
    private final RegisteredClient introspectingClient = RegisteredClient.withId("introspecting-registration")
            .clientId("introspecting-client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .build();

    @Test
    void introspectsAnotherClientsActiveAccessTokenAndIgnoresHintForLookup() {
        OAuth2Authorization authorization = authorization("access-token", ISSUED_AT, ISSUED_AT.plusSeconds(300),
                metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, Map.of(
                        "iss", "https://issuer.example",
                        "sub", "machine-subject",
                        "aud", Set.of("resource-api"),
                        "iat", ISSUED_AT,
                        "exp", ISSUED_AT.plusSeconds(300),
                        "nbf", ISSUED_AT,
                        "jti", "token-id",
                        "scope", Set.of("message.read", "message.write"),
                        "custom", "value")));
        RecordingAuthorizationService authorizations = new RecordingAuthorizationService(authorization);
        OAuth2TokenIntrospectionAuthenticationProvider provider = provider(authorizations);
        OAuth2TokenIntrospectionAuthenticationToken request = request("access-token", "refresh_token");

        OAuth2TokenIntrospectionAuthenticationToken result = provider.authenticate(request);

        assertTrue(result.isAuthenticated());
        OAuth2TokenIntrospection claims = result.getTokenClaims();
        assertTrue(claims.isActive());
        assertEquals("authorized-client", claims.getClientId());
        assertNull(claims.getUsername());
        assertEquals("Bearer", claims.getTokenType());
        assertEquals(Set.of("message.read", "message.write"), Set.copyOf(claims.getScopes()));
        assertEquals(List.of("resource-api"), claims.getAudience());
        assertEquals("machine-subject", claims.getSubject());
        assertEquals("https://issuer.example", claims.getIssuer().toString());
        assertEquals("token-id", claims.getId());
        assertEquals("value", claims.getClaim("custom"));
        assertEquals(ISSUED_AT, claims.getIssuedAt());
        assertEquals(ISSUED_AT.plusSeconds(300), claims.getExpiresAt());
        assertEquals(ISSUED_AT, claims.getNotBefore());
        assertEquals("access-token", authorizations.requestedToken);
        assertNull(authorizations.requestedTokenType);
        assertEquals("introspecting-client", result.getPrincipal().getPrincipal().getName());
    }

    @Test
    void unknownTokenReturnsOriginalUnauthenticatedRequestWithOnlyActiveFalse() {
        OAuth2TokenIntrospectionAuthenticationToken request = request("unknown", null);

        OAuth2TokenIntrospectionAuthenticationToken result = provider(
                new InMemoryOAuth2AuthorizationService()).authenticate(request);

        assertSame(request, result);
        assertFalse(result.isAuthenticated());
        assertEquals(Map.of("active", false), result.getTokenClaims().getClaims());
    }

    @Test
    void introspectsActiveRefreshTokenWithoutInventingAccessTokenClaims() {
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "refresh-token", ISSUED_AT, ISSUED_AT.plusSeconds(600));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(this.authorizedClient)
                .principalName("machine-subject")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .refreshToken(refreshToken)
                .build();

        OAuth2TokenIntrospection tokenClaims = provider(new InMemoryOAuth2AuthorizationService(authorization))
                .authenticate(request("refresh-token", "access_token")).getTokenClaims();

        assertTrue(tokenClaims.isActive());
        assertEquals("authorized-client", tokenClaims.getClientId());
        assertEquals(ISSUED_AT, tokenClaims.getIssuedAt());
        assertEquals(ISSUED_AT.plusSeconds(600), tokenClaims.getExpiresAt());
        assertNull(tokenClaims.getTokenType());
        assertNull(tokenClaims.getScopes());
        assertNull(tokenClaims.getAudience());
        assertEquals(4, tokenClaims.getClaims().size());
    }

    @Test
    void inactiveTokensReturnNoOtherClaims() {
        Instant now = Instant.now();
        OAuth2Authorization invalidated = authorization("invalidated", now, now.plusSeconds(300),
                metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
        OAuth2Authorization expired = authorization("expired", now.minusSeconds(600), now.minusSeconds(300),
                metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                        Map.of("sub", "must-not-leak")));
        OAuth2Authorization beforeUse = authorization("before-use", now, now.plusSeconds(600),
                metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                        Map.of("nbf", now.plusSeconds(300), "sub", "must-not-leak")));

        for (OAuth2Authorization authorization : List.of(invalidated, expired, beforeUse)) {
            OAuth2TokenIntrospectionAuthenticationToken result = provider(
                    new InMemoryOAuth2AuthorizationService(authorization))
                    .authenticate(request(authorization.getAccessToken().getToken().getTokenValue(), "access_token"));

            assertTrue(result.isAuthenticated());
            assertEquals(Map.of("active", false), result.getTokenClaims().getClaims());
        }
    }

    @Test
    void requiresAuthenticatedQuarkusClientIdentity() {
        SecurityIdentity anonymous = QuarkusSecurityIdentity.builder().setAnonymous(true)
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, this.introspectingClient)
                .build();
        SecurityIdentity applicationUser = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("application-user"))
                .build();
        OAuth2TokenIntrospectionAuthenticationProvider provider = provider(new InMemoryOAuth2AuthorizationService());

        for (SecurityIdentity identity : List.of(anonymous, applicationUser)) {
            OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                    () -> provider.authenticate(new OAuth2TokenIntrospectionAuthenticationToken(
                            "token", identity, null, Map.of())));
            assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
        }
    }

    private OAuth2TokenIntrospectionAuthenticationProvider provider(OAuth2AuthorizationService authorizations) {
        return new OAuth2TokenIntrospectionAuthenticationProvider(
                new InMemoryRegisteredClientRepository(this.authorizedClient, this.introspectingClient),
                authorizations);
    }

    private OAuth2TokenIntrospectionAuthenticationToken request(String token, String hint) {
        return new OAuth2TokenIntrospectionAuthenticationToken(
                token, clientIdentity(this.introspectingClient), hint, Map.of());
    }

    private OAuth2Authorization authorization(String tokenValue, Instant issuedAt, Instant expiresAt,
            java.util.function.Consumer<Map<String, Object>> metadataConsumer) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, tokenValue, issuedAt, expiresAt,
                Set.of("message.read", "message.write"));
        return OAuth2Authorization.withRegisteredClient(this.authorizedClient)
                .principalName("machine-subject")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(accessToken.getScopes())
                .token(accessToken, metadataConsumer)
                .build();
    }

    private static SecurityIdentity clientIdentity(RegisteredClient registeredClient) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, registeredClient)
                .build();
    }

    private static final class RecordingAuthorizationService implements OAuth2AuthorizationService {

        private final InMemoryOAuth2AuthorizationService delegate;
        private String requestedToken;
        private OAuth2TokenType requestedTokenType;

        private RecordingAuthorizationService(OAuth2Authorization authorization) {
            this.delegate = new InMemoryOAuth2AuthorizationService(authorization);
        }

        @Override
        public void save(OAuth2Authorization authorization) {
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
            this.requestedToken = token;
            this.requestedTokenType = tokenType;
            return this.delegate.findByToken(token, tokenType);
        }
    }
}
