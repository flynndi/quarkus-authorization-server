package io.quarkiverse.authorization.server.endpoint;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;

/**
 * A representation of an OAuth 2.0 Device Authorization Response.
 */
public final class OAuth2DeviceAuthorizationResponse {

    private OAuth2DeviceCode deviceCode;
    private OAuth2UserCode userCode;
    private String verificationUri;
    private String verificationUriComplete;
    private long interval;
    private Map<String, Object> additionalParameters;

    private OAuth2DeviceAuthorizationResponse() {
    }

    public OAuth2DeviceCode getDeviceCode() {
        return this.deviceCode;
    }

    public OAuth2UserCode getUserCode() {
        return this.userCode;
    }

    public String getVerificationUri() {
        return this.verificationUri;
    }

    public String getVerificationUriComplete() {
        return this.verificationUriComplete;
    }

    public long getInterval() {
        return this.interval;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    public static Builder with(String deviceCode, String userCode) {
        return new Builder(
                Arguments.requireNonBlank(deviceCode, "deviceCode"),
                Arguments.requireNonBlank(userCode, "userCode"));
    }

    public static Builder with(OAuth2DeviceCode deviceCode, OAuth2UserCode userCode) {
        return new Builder(
                Objects.requireNonNull(deviceCode, "deviceCode cannot be null"),
                Objects.requireNonNull(userCode, "userCode cannot be null"));
    }

    public static final class Builder {

        private final String deviceCode;
        private final String userCode;
        private String verificationUri;
        private String verificationUriComplete;
        private long expiresIn;
        private long interval;
        private Map<String, Object> additionalParameters;

        private Builder(OAuth2DeviceCode deviceCode, OAuth2UserCode userCode) {
            this.deviceCode = deviceCode.getTokenValue();
            this.userCode = userCode.getTokenValue();
            this.expiresIn = ChronoUnit.SECONDS.between(deviceCode.getIssuedAt(), deviceCode.getExpiresAt());
        }

        private Builder(String deviceCode, String userCode) {
            this.deviceCode = deviceCode;
            this.userCode = userCode;
        }

        public Builder verificationUri(String verificationUri) {
            this.verificationUri = verificationUri;
            return this;
        }

        public Builder verificationUriComplete(String verificationUriComplete) {
            this.verificationUriComplete = verificationUriComplete;
            return this;
        }

        public Builder expiresIn(long expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }

        public Builder interval(long interval) {
            this.interval = interval;
            return this;
        }

        public Builder additionalParameters(Map<String, Object> additionalParameters) {
            this.additionalParameters = additionalParameters;
            return this;
        }

        public OAuth2DeviceAuthorizationResponse build() {
            Arguments.requireNonBlank(this.verificationUri, "verificationUri");
            if (this.expiresIn <= 0) {
                throw new IllegalArgumentException("expiresIn must be greater than zero");
            }

            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plusSeconds(this.expiresIn);
            OAuth2DeviceAuthorizationResponse response = new OAuth2DeviceAuthorizationResponse();
            response.deviceCode = new OAuth2DeviceCode(this.deviceCode, issuedAt, expiresAt);
            response.userCode = new OAuth2UserCode(this.userCode, issuedAt, expiresAt);
            response.verificationUri = this.verificationUri;
            response.verificationUriComplete = this.verificationUriComplete;
            response.interval = this.interval;
            response.additionalParameters = Collections.unmodifiableMap(this.additionalParameters == null
                    ? Collections.emptyMap()
                    : new LinkedHashMap<>(this.additionalParameters));
            return response;
        }
    }
}
