package io.quarkiverse.authorization.server.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;

class TokenSettingsTest {

    @Test
    void defaultsAndConfiguresIdTokenSignatureAlgorithm() {
        assertEquals(SignatureAlgorithm.RS256,
                TokenSettings.builder().build().getIdTokenSignatureAlgorithm());
        assertEquals(SignatureAlgorithm.ES256,
                TokenSettings.builder().idTokenSignatureAlgorithm(SignatureAlgorithm.ES256)
                        .build().getIdTokenSignatureAlgorithm());
        assertThrows(NullPointerException.class,
                () -> TokenSettings.builder().idTokenSignatureAlgorithm(null));
    }

    @Test
    void providesDefaultTokenSettings() {
        TokenSettings settings = TokenSettings.builder().build();

        assertEquals(Duration.ofMinutes(5), settings.getAuthorizationCodeTimeToLive());
        assertEquals(Duration.ofMinutes(5), settings.getAccessTokenTimeToLive());
        assertSame(OAuth2TokenFormat.SELF_CONTAINED, settings.getAccessTokenFormat());
        assertEquals(Duration.ofMinutes(5), settings.getDeviceCodeTimeToLive());
        assertTrue(settings.isReuseRefreshTokens());
        assertEquals(Duration.ofMinutes(60), settings.getRefreshTokenTimeToLive());
        assertTrue(settings.getSettings().containsKey(ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE));
    }

    @Test
    void acceptsPositiveAccessTokenTimeToLive() {
        TokenSettings tokenSettings = TokenSettings.builder()
                .authorizationCodeTimeToLive(Duration.ofMinutes(3))
                .accessTokenTimeToLive(Duration.ofMinutes(10))
                .deviceCodeTimeToLive(Duration.ofMinutes(7))
                .reuseRefreshTokens(false)
                .refreshTokenTimeToLive(Duration.ofHours(2))
                .build();

        assertEquals(Duration.ofMinutes(3), tokenSettings.getAuthorizationCodeTimeToLive());
        assertEquals(Duration.ofMinutes(10), tokenSettings.getAccessTokenTimeToLive());
        assertEquals(Duration.ofMinutes(7), tokenSettings.getDeviceCodeTimeToLive());
        assertFalse(tokenSettings.isReuseRefreshTokens());
        assertEquals(Duration.ofHours(2), tokenSettings.getRefreshTokenTimeToLive());
    }

    @Test
    void rejectsNullZeroAndNegativeAccessTokenTimeToLive() {
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().authorizationCodeTimeToLive(null));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().authorizationCodeTimeToLive(Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().authorizationCodeTimeToLive(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().accessTokenTimeToLive(null));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().accessTokenTimeToLive(Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().deviceCodeTimeToLive(null));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().deviceCodeTimeToLive(Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().deviceCodeTimeToLive(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().refreshTokenTimeToLive(null));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().refreshTokenTimeToLive(Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> TokenSettings.builder().refreshTokenTimeToLive(Duration.ofSeconds(-1)));
    }

    @Test
    void createsTokenSettingsFromSettingsMap() {
        TokenSettings settings = TokenSettings.withSettings(Map.of(
                ConfigurationSettingNames.Token.AUTHORIZATION_CODE_TIME_TO_LIVE, Duration.ofMinutes(4),
                ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE, Duration.ofMinutes(15),
                ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT, OAuth2TokenFormat.REFERENCE,
                ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE, Duration.ofMinutes(8),
                ConfigurationSettingNames.Token.REUSE_REFRESH_TOKENS, false,
                ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE, Duration.ofHours(3)))
                .build();

        assertEquals(Duration.ofMinutes(4), settings.getAuthorizationCodeTimeToLive());
        assertEquals(Duration.ofMinutes(15), settings.getAccessTokenTimeToLive());
        assertSame(OAuth2TokenFormat.REFERENCE, settings.getAccessTokenFormat());
        assertEquals(Duration.ofMinutes(8), settings.getDeviceCodeTimeToLive());
        assertFalse(settings.isReuseRefreshTokens());
        assertEquals(Duration.ofHours(3), settings.getRefreshTokenTimeToLive());
        assertThrows(UnsupportedOperationException.class,
                () -> settings.getSettings().put("another", "value"));
    }
}
