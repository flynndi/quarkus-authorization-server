package io.quarkiverse.authorization.server.runtime.http.converter;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.endpoint.OAuth2DeviceAuthorizationResponse;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.vertx.core.http.HttpServerResponse;

/**
 * Writes an OAuth 2.0 Device Authorization Response as JSON.
 */
@Singleton
public final class OAuth2DeviceAuthorizationResponseHttpMessageConverter
        extends AbstractOAuth2HttpMessageConverter {

    @Inject
    public OAuth2DeviceAuthorizationResponseHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    public void write(OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse,
            HttpServerResponse response) {
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.DEVICE_CODE,
                deviceAuthorizationResponse.getDeviceCode().getTokenValue());
        parameters.put(OAuth2ParameterNames.USER_CODE,
                deviceAuthorizationResponse.getUserCode().getTokenValue());
        parameters.put(OAuth2ParameterNames.VERIFICATION_URI,
                deviceAuthorizationResponse.getVerificationUri());
        if (Arguments.hasText(deviceAuthorizationResponse.getVerificationUriComplete())) {
            parameters.put(OAuth2ParameterNames.VERIFICATION_URI_COMPLETE,
                    deviceAuthorizationResponse.getVerificationUriComplete());
        }
        parameters.put(OAuth2ParameterNames.EXPIRES_IN, getExpiresIn(deviceAuthorizationResponse));
        if (deviceAuthorizationResponse.getInterval() > 0) {
            parameters.put(OAuth2ParameterNames.INTERVAL, deviceAuthorizationResponse.getInterval());
        }
        parameters.putAll(deviceAuthorizationResponse.getAdditionalParameters());
        writeJson(parameters, response);
    }

    private static long getExpiresIn(OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse) {
        Instant expiresAt = deviceAuthorizationResponse.getDeviceCode().getExpiresAt();
        if (expiresAt == null) {
            return -1;
        }
        Instant issuedAt = deviceAuthorizationResponse.getDeviceCode().getIssuedAt();
        return ChronoUnit.SECONDS.between(issuedAt != null ? issuedAt : Instant.now(), expiresAt);
    }
}
