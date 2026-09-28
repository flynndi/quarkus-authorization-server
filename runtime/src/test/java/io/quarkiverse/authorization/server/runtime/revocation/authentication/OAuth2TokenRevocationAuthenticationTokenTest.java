package io.quarkiverse.authorization.server.runtime.revocation.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OAuth2TokenRevocationAuthenticationTokenTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("client"))
            .build();

    @Test
    void requestConstructorIsUnauthenticated() {
        OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
                "token", CLIENT_PRINCIPAL, "access_token");

        assertEquals("token", authentication.getToken());
        assertSame(CLIENT_PRINCIPAL, authentication.getPrincipal());
        assertEquals("access_token", authentication.getTokenTypeHint());
        assertEquals("", authentication.getCredentials());
        assertFalse(authentication.isAuthenticated());
    }

    @Test
    void resultConstructorIsAuthenticated() {
        OAuth2RefreshToken revokedToken = new OAuth2RefreshToken(
                "refresh-token", Instant.now(), Instant.now().plusSeconds(60));

        OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(revokedToken,
                CLIENT_PRINCIPAL);

        assertEquals("refresh-token", authentication.getToken());
        assertSame(CLIENT_PRINCIPAL, authentication.getPrincipal());
        assertNull(authentication.getTokenTypeHint());
        assertTrue(authentication.isAuthenticated());
    }

    @Test
    void validatesRequiredConstructorArguments() {
        assertThrows(IllegalArgumentException.class,
                () -> new OAuth2TokenRevocationAuthenticationToken(" ", CLIENT_PRINCIPAL, null));
        assertThrows(NullPointerException.class,
                () -> new OAuth2TokenRevocationAuthenticationToken("token", null, null));
        assertThrows(NullPointerException.class,
                () -> new OAuth2TokenRevocationAuthenticationToken(null, CLIENT_PRINCIPAL));
        OAuth2RefreshToken token = new OAuth2RefreshToken(
                "token", Instant.now(), Instant.now().plusSeconds(60));
        assertThrows(NullPointerException.class,
                () -> new OAuth2TokenRevocationAuthenticationToken(token, null));
    }
}
