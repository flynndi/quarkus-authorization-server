package io.quarkiverse.authorization.server.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;

class OAuth2DeviceAuthorizationResponseTest {

    @Test
    void buildsResponseFromCodes() {
        Instant issuedAt = Instant.parse("2026-09-04T01:00:00Z");
        OAuth2DeviceAuthorizationResponse response = OAuth2DeviceAuthorizationResponse.with(
                new OAuth2DeviceCode("device-code", issuedAt, issuedAt.plusSeconds(300)),
                new OAuth2UserCode("BCDF-GHJK", issuedAt, issuedAt.plusSeconds(300)))
                .verificationUri("https://issuer.example/device")
                .verificationUriComplete("https://issuer.example/device?user_code=BCDF-GHJK")
                .interval(5)
                .additionalParameters(Map.of("custom", "value"))
                .build();

        assertEquals("device-code", response.getDeviceCode().getTokenValue());
        assertEquals("BCDF-GHJK", response.getUserCode().getTokenValue());
        assertEquals("https://issuer.example/device", response.getVerificationUri());
        assertEquals(5, response.getInterval());
        assertEquals(Map.of("custom", "value"), response.getAdditionalParameters());
    }

    @Test
    void requiresCodesUriAndPositiveLifetime() {
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2DeviceAuthorizationResponse.with("", "user-code"));
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2DeviceAuthorizationResponse.with("device-code", "user-code")
                        .expiresIn(300).build());
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2DeviceAuthorizationResponse.with("device-code", "user-code")
                        .verificationUri("https://issuer.example/device").build());
    }
}
