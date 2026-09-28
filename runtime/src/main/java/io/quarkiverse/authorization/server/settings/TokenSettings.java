package io.quarkiverse.authorization.server.settings;

import java.io.Serial;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;

/**
 * Configuration settings for tokens issued to a registered client.
 */
public final class TokenSettings extends AbstractSettings {

    @Serial
    private static final long serialVersionUID = 418543921923446911L;

    private TokenSettings(Map<String, Object> settings) {
        super(settings);
    }

    /**
     * Returns the time-to-live for an authorization code. The default is five minutes.
     */
    public Duration getAuthorizationCodeTimeToLive() {
        return getSetting(ConfigurationSettingNames.Token.AUTHORIZATION_CODE_TIME_TO_LIVE);
    }

    /**
     * Returns the time-to-live for an access token. The default is five minutes.
     */
    public Duration getAccessTokenTimeToLive() {
        return getSetting(ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE);
    }

    /**
     * Returns the access token format. The default is self-contained.
     */
    public OAuth2TokenFormat getAccessTokenFormat() {
        return getSetting(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT);
    }

    /**
     * Returns the time-to-live for a device code and user code. The default is five minutes.
     */
    public Duration getDeviceCodeTimeToLive() {
        return getSetting(ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE);
    }

    /**
     * Returns whether refresh tokens are reused. The default is {@code true}.
     */
    public boolean isReuseRefreshTokens() {
        return getSetting(ConfigurationSettingNames.Token.REUSE_REFRESH_TOKENS);
    }

    /**
     * Returns the time-to-live for a refresh token. The default is 60 minutes.
     */
    public Duration getRefreshTokenTimeToLive() {
        return getSetting(ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE);
    }

    /** Returns the ID Token signing algorithm. Newly built settings default to RS256. */
    public SignatureAlgorithm getIdTokenSignatureAlgorithm() {
        return getSetting(ConfigurationSettingNames.Token.ID_TOKEN_SIGNATURE_ALGORITHM);
    }

    public static Builder builder() {
        return new Builder()
                .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                .accessTokenTimeToLive(Duration.ofMinutes(5))
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .deviceCodeTimeToLive(Duration.ofMinutes(5))
                .reuseRefreshTokens(true)
                .refreshTokenTimeToLive(Duration.ofMinutes(60))
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256);
    }

    public static Builder withSettings(Map<String, Object> settings) {
        if (settings == null || settings.isEmpty()) {
            throw new IllegalArgumentException("settings cannot be empty");
        }
        return new Builder().settings(values -> values.putAll(settings));
    }

    public static final class Builder extends AbstractBuilder<TokenSettings, Builder> {

        private Builder() {
        }

        public Builder authorizationCodeTimeToLive(Duration authorizationCodeTimeToLive) {
            if (authorizationCodeTimeToLive == null) {
                throw new IllegalArgumentException("authorizationCodeTimeToLive cannot be null");
            }
            if (authorizationCodeTimeToLive.getSeconds() <= 0) {
                throw new IllegalArgumentException(
                        "authorizationCodeTimeToLive must be greater than Duration.ZERO");
            }
            return setting(ConfigurationSettingNames.Token.AUTHORIZATION_CODE_TIME_TO_LIVE,
                    authorizationCodeTimeToLive);
        }

        public Builder accessTokenTimeToLive(Duration accessTokenTimeToLive) {
            if (accessTokenTimeToLive == null) {
                throw new IllegalArgumentException("accessTokenTimeToLive cannot be null");
            }
            if (accessTokenTimeToLive.getSeconds() <= 0) {
                throw new IllegalArgumentException("accessTokenTimeToLive must be greater than Duration.ZERO");
            }
            return setting(ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE, accessTokenTimeToLive);
        }

        public Builder accessTokenFormat(OAuth2TokenFormat accessTokenFormat) {
            return setting(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT,
                    Objects.requireNonNull(accessTokenFormat, "accessTokenFormat cannot be null"));
        }

        public Builder deviceCodeTimeToLive(Duration deviceCodeTimeToLive) {
            if (deviceCodeTimeToLive == null) {
                throw new IllegalArgumentException("deviceCodeTimeToLive cannot be null");
            }
            if (deviceCodeTimeToLive.getSeconds() <= 0) {
                throw new IllegalArgumentException("deviceCodeTimeToLive must be greater than Duration.ZERO");
            }
            return setting(ConfigurationSettingNames.Token.DEVICE_CODE_TIME_TO_LIVE, deviceCodeTimeToLive);
        }

        public Builder reuseRefreshTokens(boolean reuseRefreshTokens) {
            return setting(ConfigurationSettingNames.Token.REUSE_REFRESH_TOKENS, reuseRefreshTokens);
        }

        public Builder refreshTokenTimeToLive(Duration refreshTokenTimeToLive) {
            if (refreshTokenTimeToLive == null) {
                throw new IllegalArgumentException("refreshTokenTimeToLive cannot be null");
            }
            if (refreshTokenTimeToLive.getSeconds() <= 0) {
                throw new IllegalArgumentException("refreshTokenTimeToLive must be greater than Duration.ZERO");
            }
            return setting(ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE, refreshTokenTimeToLive);
        }

        public Builder idTokenSignatureAlgorithm(SignatureAlgorithm algorithm) {
            return setting(ConfigurationSettingNames.Token.ID_TOKEN_SIGNATURE_ALGORITHM,
                    Objects.requireNonNull(algorithm, "idTokenSignatureAlgorithm cannot be null"));
        }

        @Override
        public TokenSettings build() {
            return new TokenSettings(getSettings());
        }
    }
}
