package io.quarkiverse.authorization.server.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class OAuth2DeviceCodeTest {

    @Test
    void validatesDeviceAndUserCodes() {
        Instant issuedAt = Instant.parse("2026-09-04T01:00:00Z");
        Instant expiresAt = issuedAt.plusSeconds(300);
        OAuth2DeviceCode deviceCode = new OAuth2DeviceCode("device-code", issuedAt, expiresAt);
        OAuth2UserCode userCode = new OAuth2UserCode("BCDF-GHJK", issuedAt, expiresAt);

        assertEquals("device-code", deviceCode.getTokenValue());
        assertEquals("BCDF-GHJK", userCode.getTokenValue());
        assertEquals(issuedAt, deviceCode.getIssuedAt());
        assertEquals(expiresAt, userCode.getExpiresAt());
        assertThrows(IllegalArgumentException.class,
                () -> new OAuth2DeviceCode("", issuedAt, expiresAt));
        assertThrows(IllegalArgumentException.class,
                () -> new OAuth2UserCode("user-code", issuedAt, issuedAt));
    }
}
