package io.quarkiverse.authorization.server.runtime.token;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkus.arc.DefaultBean;

/**
 * Default token customizer used when the application does not provide one.
 */
@Singleton
@DefaultBean
public final class NoopJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
    }
}
