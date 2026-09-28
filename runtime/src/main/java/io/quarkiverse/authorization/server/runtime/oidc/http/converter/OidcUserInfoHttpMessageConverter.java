package io.quarkiverse.authorization.server.runtime.oidc.http.converter;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.oidc.OidcUserInfo;
import io.quarkiverse.authorization.server.runtime.http.converter.AbstractOAuth2HttpMessageConverter;
import io.vertx.core.http.HttpServerResponse;

@Singleton
public final class OidcUserInfoHttpMessageConverter extends AbstractOAuth2HttpMessageConverter {
    @Inject
    public OidcUserInfoHttpMessageConverter(ObjectMapper mapper) {
        super(mapper);
    }

    public void write(OidcUserInfo userInfo, HttpServerResponse response) {
        writeJson(userInfo.getClaims(), response);
    }
}
