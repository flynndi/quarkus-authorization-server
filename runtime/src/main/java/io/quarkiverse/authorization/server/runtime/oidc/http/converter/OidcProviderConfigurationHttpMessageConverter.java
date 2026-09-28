package io.quarkiverse.authorization.server.runtime.oidc.http.converter;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.oidc.OidcProviderConfiguration;
import io.quarkiverse.authorization.server.runtime.http.converter.AbstractOAuth2HttpMessageConverter;
import io.vertx.core.http.HttpServerResponse;

/**
 * Writes OpenID Provider metadata through the application's Jackson ObjectMapper.
 */
@Singleton
public final class OidcProviderConfigurationHttpMessageConverter extends AbstractOAuth2HttpMessageConverter {

    @Inject
    public OidcProviderConfigurationHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    public void write(OidcProviderConfiguration configuration, HttpServerResponse response) {
        writeJson(configuration.getClaims(), response);
    }
}
