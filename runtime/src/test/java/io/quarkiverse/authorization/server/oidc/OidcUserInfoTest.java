package io.quarkiverse.authorization.server.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class OidcUserInfoTest {
    @Test
    void standardClaimsAndAddressAreTypedAndClaimsAreCopied() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "alice");
        claims.put("email_verified", "true");
        claims.put("updated_at", 1700000000L);
        claims.put("address", Map.of("country", "CN", "locality", "Shanghai"));
        OidcUserInfo userInfo = new OidcUserInfo(claims);
        claims.put("sub", "mallory");
        assertEquals("alice", userInfo.getSubject());
        assertTrue(userInfo.getEmailVerified());
        assertEquals(Instant.ofEpochSecond(1700000000), userInfo.getUpdatedAt());
        assertEquals("CN", userInfo.getAddress().getCountry());
        assertEquals("Shanghai", userInfo.getAddress().getLocality());
        assertThrows(UnsupportedOperationException.class, () -> userInfo.getClaims().put("sub", "mallory"));
    }

    @Test
    void builderUsesTheSameStandardClaimsAsIdToken() {
        OidcUserInfo userInfo = OidcUserInfo.builder().subject("alice").name("Alice").givenName("A")
                .familyName("Lice").middleName("M").nickname("ali").preferredUsername("alice")
                .email("alice@example.com").emailVerified(true).phoneNumber("+123").phoneNumberVerified(false)
                .profile("https://example.com/alice").picture("https://example.com/alice.png")
                .website("https://example.com").gender("female").birthdate("2000-01-01").zoneinfo("Asia/Shanghai")
                .locale("zh-CN").updatedAt("2026-09-03T00:00:00Z")
                .claims(claims -> claims.put("address", Map.of("country", "CN"))).build();
        assertEquals("Alice", userInfo.getFullName());
        assertEquals("ali", userInfo.getNickName());
        assertFalse(userInfo.getPhoneNumberVerified());
        assertEquals(userInfo, new OidcUserInfo(userInfo.getClaims()));
        assertEquals(userInfo.hashCode(), new OidcUserInfo(userInfo.getClaims()).hashCode());
        OidcIdToken token = new OidcIdToken("id", Instant.now(), Instant.now().plusSeconds(300), userInfo.getClaims());
        assertEquals(userInfo.getEmail(), token.getEmail());
        assertEquals(userInfo.getAddress(), token.getAddress());
    }

    @Test
    void rejectsEmptyClaimsAndInvalidTypedClaimsWithoutInventingDefaults() {
        assertThrows(IllegalArgumentException.class, () -> new OidcUserInfo(Map.of()));
        assertThrows(IllegalArgumentException.class, () -> OidcUserInfo.builder().build());
        OidcUserInfo emptyFields = OidcUserInfo.builder().subject("alice").build();
        assertNull(emptyFields.getEmailVerified());
        assertNull(emptyFields.getAddress().getCountry());
        assertThrows(IllegalArgumentException.class,
                () -> new OidcUserInfo(Map.of("email_verified", "maybe")).getEmailVerified());
        assertThrows(IllegalArgumentException.class,
                () -> new OidcUserInfo(Map.of("address", "not-an-object")).getAddress());
    }
}
