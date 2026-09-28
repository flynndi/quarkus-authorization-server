package io.quarkiverse.authorization.server.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class OAuth2AuthorizationCodeTest {

    @Test
    void validatesAndStoresAuthorizationCode() {
        Instant issuedAt = Instant.parse("2026-09-01T01:00:00Z");
        Instant expiresAt = issuedAt.plusSeconds(300);
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("authorization-code", issuedAt, expiresAt);

        assertEquals("authorization-code", authorizationCode.getTokenValue());
        assertEquals(issuedAt, authorizationCode.getIssuedAt());
        assertEquals(expiresAt, authorizationCode.getExpiresAt());
        assertThrows(IllegalArgumentException.class,
                () -> new OAuth2AuthorizationCode("", issuedAt, expiresAt));
        assertThrows(IllegalArgumentException.class,
                () -> new OAuth2AuthorizationCode("authorization-code", issuedAt, issuedAt));
    }
}
