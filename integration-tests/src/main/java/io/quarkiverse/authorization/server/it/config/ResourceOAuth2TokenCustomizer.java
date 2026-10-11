package io.quarkiverse.authorization.server.it.config;

import jakarta.inject.Singleton;
import jakarta.ws.rs.Produces;

import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;

@Produces
@Singleton
public class ResourceOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {
        context.getClaims().claim("groups", context.getPrincipal().getRoles());
    }
}
