package io.quarkiverse.authorization.server.runtime.revocation.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OAuth2TokenRevocationAuthenticationProviderTest {

    private static final Instant ISSUED_AT = Instant.now().minusSeconds(60);

    private final RegisteredClient registeredClient = RegisteredClient.withId("client-registration")
            .clientId("client")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("https://client.example/callback")
            .build();
    private final RegisteredClient otherClient = RegisteredClient.withId("other-registration")
            .clientId("other-client")
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .build();

    @Test
    void unknownTokenReturnsOriginalRequestWithoutSaving() {
        RecordingAuthorizationService authorizations = new RecordingAuthorizationService();
        OAuth2TokenRevocationAuthenticationToken request = request("unknown", "access_token");

        OAuth2TokenRevocationAuthenticationToken result = provider(authorizations)
                .authenticate(request);

        assertSame(request, result);
        assertFalse(result.isAuthenticated());
        assertEquals(0, authorizations.saveCount);
        assertEquals("unknown", authorizations.requestedToken);
        assertNull(authorizations.requestedTokenType);
    }

    @Test
    void tokenIssuedToAnotherClientIsRejected() {
        RecordingAuthorizationService authorizations = new RecordingAuthorizationService(
                authorization(this.otherClient, "other"));

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> provider(authorizations).authenticate(new OAuth2TokenRevocationAuthenticationToken(
                        "access-other", clientIdentity(this.registeredClient), "access_token")));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
        assertEquals(0, authorizations.saveCount);
    }

    @Test
    void refreshTokenRevocationCascadesToAccessTokenAndAuthorizationCode() {
        OAuth2Authorization authorization = authorization(this.registeredClient, "refresh");
        RecordingAuthorizationService authorizations = new RecordingAuthorizationService(authorization);

        OAuth2TokenRevocationAuthenticationToken result = provider(authorizations)
                .authenticate(request("refresh-refresh", "access_token"));

        assertTrue(result.isAuthenticated());
        assertEquals("refresh-refresh", result.getToken());
        assertEquals(1, authorizations.saveCount);
        assertEquals("refresh-refresh", authorizations.requestedToken);
        assertNull(authorizations.requestedTokenType);
        OAuth2Authorization saved = authorizations.findById(authorization.getId());
        assertTrue(saved.getRefreshToken().isInvalidated());
        assertTrue(saved.getAccessToken().isInvalidated());
        assertTrue(saved.getAuthorizationCode().isInvalidated());
        assertEquals(Set.of("message.read"), saved.getAuthorizedScopes());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void revokesRefreshTokenWithoutAccessTokenAndCanRepeat(boolean withCode) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(this.registeredClient)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .refreshToken(new OAuth2RefreshToken("refresh-only", ISSUED_AT, ISSUED_AT.plusSeconds(1200)));
        if (withCode) {
            builder.authorizationCode(new OAuth2AuthorizationCode("code", ISSUED_AT, ISSUED_AT.plusSeconds(300)));
        }
        OAuth2Authorization original = builder.build();
        RecordingAuthorizationService authorizations = new RecordingAuthorizationService(original);
        OAuth2TokenRevocationAuthenticationProvider provider = provider(authorizations);

        assertTrue(provider.authenticate(request("refresh-only", "refresh_token")).isAuthenticated());
        OAuth2Authorization revoked = authorizations.findById(original.getId());
        assertTrue(revoked.getRefreshToken().isInvalidated());
        assertNull(revoked.getAccessToken());
        if (withCode) {
            assertTrue(revoked.getAuthorizationCode().isInvalidated());
        } else {
            assertNull(revoked.getAuthorizationCode());
        }
        assertTrue(provider.authenticate(request("refresh-only", "refresh_token")).isAuthenticated());
        assertEquals(revoked, authorizations.findById(original.getId()));
        assertEquals(2, authorizations.saveCount);
        assertFalse(original.getRefreshToken().isInvalidated());
    }

    @Test
    void accessTokenRevocationDoesNotInvalidateRefreshTokenOrAuthorizationCode() {
        OAuth2Authorization authorization = authorization(this.registeredClient, "access");
        RecordingAuthorizationService authorizations = new RecordingAuthorizationService(authorization);

        OAuth2TokenRevocationAuthenticationToken result = provider(authorizations)
                .authenticate(request("access-access", "refresh_token"));

        assertTrue(result.isAuthenticated());
        OAuth2Authorization saved = authorizations.findById(authorization.getId());
        assertTrue(saved.getAccessToken().isInvalidated());
        assertFalse(saved.getRefreshToken().isInvalidated());
        assertFalse(saved.getAuthorizationCode().isInvalidated());
        assertEquals(Set.of("message.read"), saved.getAuthorizedScopes());
    }

    @Test
    void repeatedRevocationRemainsSuccessful() {
        OAuth2Authorization authorization = authorization(this.registeredClient, "repeat");
        RecordingAuthorizationService authorizations = new RecordingAuthorizationService(authorization);
        OAuth2TokenRevocationAuthenticationProvider provider = provider(authorizations);

        OAuth2TokenRevocationAuthenticationToken first = provider.authenticate(request(
                "access-repeat", null));
        OAuth2TokenRevocationAuthenticationToken second = provider.authenticate(request(
                "access-repeat", null));

        assertTrue(first.isAuthenticated());
        assertTrue(second.isAuthenticated());
        assertEquals(2, authorizations.saveCount);
        assertTrue(authorizations.findById(authorization.getId()).getAccessToken().isInvalidated());
    }

    @Test
    void saveFailureIsPropagated() {
        IllegalStateException saveFailure = new IllegalStateException("save failed");
        OAuth2AuthorizationService authorizations = new RecordingAuthorizationService(
                authorization(this.registeredClient, "failure")) {
            @Override
            public void save(OAuth2Authorization authorization) {
                throw saveFailure;
            }
        };

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> provider(authorizations).authenticate(request("access-failure", null)));
        assertSame(saveFailure, exception);
    }

    @Test
    void requiresAuthenticatedQuarkusClientIdentity() {
        SecurityIdentity anonymous = QuarkusSecurityIdentity.builder().setAnonymous(true)
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, this.registeredClient)
                .build();
        SecurityIdentity applicationUser = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("application-user"))
                .build();
        OAuth2TokenRevocationAuthenticationProvider provider = provider(new RecordingAuthorizationService());

        for (SecurityIdentity identity : Set.of(anonymous, applicationUser)) {
            OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                    () -> provider.authenticate(new OAuth2TokenRevocationAuthenticationToken(
                            "token", identity, null)));
            assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
        }
    }

    private OAuth2TokenRevocationAuthenticationProvider provider(OAuth2AuthorizationService authorizations) {
        return new OAuth2TokenRevocationAuthenticationProvider(authorizations);
    }

    private OAuth2TokenRevocationAuthenticationToken request(String token, String hint) {
        return new OAuth2TokenRevocationAuthenticationToken(
                token, clientIdentity(this.registeredClient), hint);
    }

    private static OAuth2Authorization authorization(RegisteredClient registeredClient, String suffix) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "access-" + suffix, ISSUED_AT, ISSUED_AT.plusSeconds(600), Set.of("message.read"));
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "refresh-" + suffix, ISSUED_AT, ISSUED_AT.plusSeconds(1200));
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "code-" + suffix, ISSUED_AT, ISSUED_AT.plusSeconds(300));
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("message.read"))
                .authorizationCode(authorizationCode)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private static SecurityIdentity clientIdentity(RegisteredClient registeredClient) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, registeredClient)
                .build();
    }

    private static class RecordingAuthorizationService implements OAuth2AuthorizationService {

        private final InMemoryOAuth2AuthorizationService delegate;
        private String requestedToken;
        private OAuth2TokenType requestedTokenType;
        private int saveCount;

        private RecordingAuthorizationService(OAuth2Authorization... authorizations) {
            this.delegate = new InMemoryOAuth2AuthorizationService(authorizations);
        }

        @Override
        public void save(OAuth2Authorization authorization) {
            this.saveCount++;
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
