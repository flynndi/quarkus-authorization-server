package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestContext;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestValidator;
import io.quarkus.arc.DefaultBean;

/** Default application policy. Protocol checks run independently. */
@Singleton
@DefaultBean
public final class NoopAuthorizationRequestValidator implements AuthorizationRequestValidator {
    @Override
    public void validate(AuthorizationRequestContext context) {
    }
}
