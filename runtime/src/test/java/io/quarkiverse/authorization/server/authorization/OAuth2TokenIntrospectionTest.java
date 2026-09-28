package io.quarkiverse.authorization.server.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class OAuth2TokenIntrospectionTest {

    @Test
    void defaultsToInactiveAndExposesStandardClaims() {
        assertFalse(OAuth2TokenIntrospection.builder().build().isActive());

        Instant issuedAt = Instant.parse("2026-09-04T01:00:00Z");
        OAuth2TokenIntrospection introspection = OAuth2TokenIntrospection.builder(true)
                .scope("message.read")
                .scope("message.write")
                .clientId("authorized-client")
                .username("resource-owner")
                .tokenType("Bearer")
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(300))
                .notBefore(issuedAt)
                .subject("subject")
                .audience("resource-api")
                .issuer("https://issuer.example")
                .id("token-id")
                .claim("custom", "value")
                .build();

        assertTrue(introspection.isActive());
        assertEquals(List.of("message.read", "message.write"), introspection.getScopes());
        assertEquals("authorized-client", introspection.getClientId());
        assertEquals("resource-owner", introspection.getUsername());
        assertEquals("Bearer", introspection.getTokenType());
        assertEquals(issuedAt, introspection.getIssuedAt());
        assertEquals(issuedAt.plusSeconds(300), introspection.getExpiresAt());
        assertEquals(issuedAt, introspection.getNotBefore());
        assertEquals("subject", introspection.getSubject());
        assertEquals(List.of("resource-api"), introspection.getAudience());
        assertEquals("https://issuer.example", introspection.getIssuer().toString());
        assertEquals("token-id", introspection.getId());
        assertEquals("value", introspection.getClaim("custom"));
    }

    @Test
    void withClaimsCopiesAndValidatesClaims() {
        Map<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put(OAuth2TokenIntrospectionClaimNames.ACTIVE, true);
        claims.put(OAuth2TokenIntrospectionClaimNames.AUD, List.of("api"));
        OAuth2TokenIntrospection introspection = OAuth2TokenIntrospection.withClaims(claims).build();
        claims.put("later", "not-visible");

        assertTrue(introspection.isActive());
        assertEquals(List.of("api"), introspection.getAudience());
        assertNull(introspection.getClaim("later"));
        assertThrows(UnsupportedOperationException.class,
                () -> introspection.getClaims().put("another", "value"));
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2TokenIntrospection.withClaims(Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2TokenIntrospection.withClaims(Map.of(
                        OAuth2TokenIntrospectionClaimNames.ACTIVE, "true")).build());
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2TokenIntrospection.builder(true).issuer("relative/path").build());
    }
}
