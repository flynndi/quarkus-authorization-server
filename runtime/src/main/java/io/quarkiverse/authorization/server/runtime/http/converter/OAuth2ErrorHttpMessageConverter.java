package io.quarkiverse.authorization.server.runtime.http.converter;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.vertx.core.http.HttpServerResponse;

/**
 * Writes an {@link OAuth2Error OAuth 2.0 Error} as an HTTP JSON response.
 */
@Singleton
public class OAuth2ErrorHttpMessageConverter extends AbstractOAuth2HttpMessageConverter {

    @Inject
    public OAuth2ErrorHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    public void write(OAuth2Error oauth2Error, HttpServerResponse response) {
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.ERROR, oauth2Error.getErrorCode());
        if (oauth2Error.getDescription() != null && !oauth2Error.getDescription().isBlank()) {
            parameters.put(OAuth2ParameterNames.ERROR_DESCRIPTION, oauth2Error.getDescription());
        }
        if (oauth2Error.getUri() != null && !oauth2Error.getUri().isBlank()) {
            parameters.put(OAuth2ParameterNames.ERROR_URI, oauth2Error.getUri());
        }

        writeJson(parameters, response);
    }
}
