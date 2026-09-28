package io.quarkiverse.authorization.server.runtime.http.converter;

import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.endpoint.OAuth2AccessTokenResponse;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerResponse;

/**
 * Writes an {@link OAuth2AccessTokenResponse} as an OAuth 2.0 JSON response.
 */
@Singleton
public class OAuth2AccessTokenResponseHttpMessageConverter extends AbstractOAuth2HttpMessageConverter {

    @Inject
    public OAuth2AccessTokenResponseHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    public void write(OAuth2AccessTokenResponse tokenResponse, HttpServerResponse response) {
        OAuth2AccessToken accessToken = tokenResponse.getAccessToken();
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.ACCESS_TOKEN, accessToken.getTokenValue());
        parameters.put(OAuth2ParameterNames.TOKEN_TYPE, accessToken.getTokenType().getValue());
        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            parameters.put(OAuth2ParameterNames.EXPIRES_IN,
                    ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }
        if (!accessToken.getScopes().isEmpty()) {
            parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", accessToken.getScopes()));
        }
        if (tokenResponse.getRefreshToken() != null) {
            parameters.put(OAuth2ParameterNames.REFRESH_TOKEN, tokenResponse.getRefreshToken().getTokenValue());
        }
        parameters.putAll(tokenResponse.getAdditionalParameters());

        response.putHeader(HttpHeaders.CACHE_CONTROL, "no-store")
                .putHeader("Pragma", "no-cache");
        writeJson(parameters, response);
    }
}
