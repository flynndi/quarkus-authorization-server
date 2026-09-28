package io.quarkiverse.authorization.server.runtime.http.converter;

import java.util.List;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.vertx.core.http.HttpServerResponse;

/**
 * Writes a public JSON Web Key Set as an HTTP JSON response.
 */
@Singleton
public final class OAuth2JwkSetHttpMessageConverter extends AbstractOAuth2HttpMessageConverter {

    @Inject
    public OAuth2JwkSetHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    public void write(List<Map<String, Object>> publicJwks, HttpServerResponse response) {
        writeJson(Map.of("keys", publicJwks), response);
    }
}
