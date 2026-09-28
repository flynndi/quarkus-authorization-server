package io.quarkiverse.authorization.server.runtime.http.converter;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.metadata.OAuth2AuthorizationServerMetadata;
import io.vertx.core.http.HttpServerResponse;

/**
 * Writes OAuth 2.0 Authorization Server Metadata as JSON.
 */
@Singleton
public final class OAuth2AuthorizationServerMetadataHttpMessageConverter extends AbstractOAuth2HttpMessageConverter {

    @Inject
    public OAuth2AuthorizationServerMetadataHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    public void write(OAuth2AuthorizationServerMetadata metadata, HttpServerResponse response) {
        writeJson(metadata.getClaims(), response);
    }
}
