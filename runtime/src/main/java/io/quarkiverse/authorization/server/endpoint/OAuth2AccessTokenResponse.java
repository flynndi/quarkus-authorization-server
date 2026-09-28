package io.quarkiverse.authorization.server.endpoint;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;

/**
 * A representation of an OAuth 2.0 Access Token Response.
 */
public final class OAuth2AccessTokenResponse {

    private OAuth2AccessToken accessToken;
    private OAuth2RefreshToken refreshToken;
    private Map<String, Object> additionalParameters;

    private OAuth2AccessTokenResponse() {
    }

    public OAuth2AccessToken getAccessToken() {
        return this.accessToken;
    }

    public OAuth2RefreshToken getRefreshToken() {
        return this.refreshToken;
    }

    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    public static Builder withToken(String tokenValue) {
        return new Builder(tokenValue);
    }

    public static final class Builder {

        private final String tokenValue;
        private OAuth2AccessToken.TokenType tokenType;
        private Instant issuedAt;
        private long expiresIn;
        private Set<String> scopes = Set.of();
        private String refreshToken;
        private Map<String, Object> additionalParameters = Map.of();

        private Builder(String tokenValue) {
            if (tokenValue == null || tokenValue.isBlank()) {
                throw new IllegalArgumentException("tokenValue cannot be empty");
            }
            this.tokenValue = tokenValue;
        }

        public Builder tokenType(OAuth2AccessToken.TokenType tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public Builder expiresIn(long expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }

        public Builder scopes(Set<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public Builder additionalParameters(Map<String, Object> additionalParameters) {
            this.additionalParameters = additionalParameters;
            return this;
        }

        public OAuth2AccessTokenResponse build() {
            this.issuedAt = Instant.now();
            Instant expiresAt = this.issuedAt.plusSeconds(this.expiresIn > 0 ? this.expiresIn : 1);
            OAuth2AccessTokenResponse response = new OAuth2AccessTokenResponse();
            response.accessToken = new OAuth2AccessToken(
                    this.tokenType, this.tokenValue, this.issuedAt, expiresAt, this.scopes);
            if (this.refreshToken != null && !this.refreshToken.isBlank()) {
                response.refreshToken = new OAuth2RefreshToken(this.refreshToken, this.issuedAt, null);
            }
            response.additionalParameters = Collections.unmodifiableMap(
                    this.additionalParameters != null ? this.additionalParameters : Map.of());
            return response;
        }
    }
}
