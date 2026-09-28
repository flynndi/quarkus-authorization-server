package io.quarkiverse.authorization.server.runtime.http.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerResponse;

/**
 * Base support for writing OAuth 2.0 protocol objects as JSON HTTP responses.
 */
public abstract class AbstractOAuth2HttpMessageConverter {

    private static final String APPLICATION_JSON_UTF_8 = "application/json;charset=UTF-8";

    private final ObjectMapper objectMapper;

    protected AbstractOAuth2HttpMessageConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    protected final void writeJson(Object value, HttpServerResponse response) {
        try {
            response.putHeader(HttpHeaders.CONTENT_TYPE, APPLICATION_JSON_UTF_8)
                    .end(this.objectMapper.writeValueAsString(value));
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to write the OAuth 2.0 JSON response", exception);
        }
    }
}
