package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentCustomizer;
import io.quarkus.arc.DefaultBean;

/** Default application policy. Protocol checks run independently. */
@Singleton
@DefaultBean
public final class NoopAuthorizationConsentCustomizer implements AuthorizationConsentCustomizer {
    @Override
    public void customize(AuthorizationConsentContext context) {
    }
}
