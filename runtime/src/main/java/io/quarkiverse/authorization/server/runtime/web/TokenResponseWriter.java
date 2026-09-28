package io.quarkiverse.authorization.server.runtime.web;

import java.time.temporal.ChronoUnit;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2AccessTokenResponse;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkus.arc.DefaultBean;
import io.vertx.ext.web.RoutingContext;

/** Writes a successful token issuance as an OAuth 2.0 HTTP response. */
@Singleton
@DefaultBean
public final class TokenResponseWriter {

    private final OAuth2AccessTokenResponseHttpMessageConverter accessTokenResponseConverter;

    @Inject
    public TokenResponseWriter(
            OAuth2AccessTokenResponseHttpMessageConverter accessTokenResponseConverter) {
        this.accessTokenResponseConverter = accessTokenResponseConverter;
    }

    public void write(RoutingContext context, TokenIssuanceResult result) {
        OAuth2AccessToken accessToken = result.getAccessToken();
        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                .tokenType(accessToken.getTokenType())
                .scopes(accessToken.getScopes());
        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            builder.expiresIn(
                    ChronoUnit.SECONDS.between(
                            accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }
        OAuth2RefreshToken refreshToken = result.getRefreshToken();
        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }
        if (!result.getAdditionalParameters().isEmpty()) {
            builder.additionalParameters(result.getAdditionalParameters());
        }
        this.accessTokenResponseConverter.write(builder.build(), context.response());
    }
}
