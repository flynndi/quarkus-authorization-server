package io.quarkiverse.authorization.server.runtime.client.registration;

import java.util.Set;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.registration.ClientRegistrationScopeValidator;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.arc.DefaultBean;

/** Default CDI scope policy that requires applications to explicitly permit dynamically registered scopes. */
@Singleton
@DefaultBean
public final class DefaultClientRegistrationScopeValidator implements ClientRegistrationScopeValidator {
    @Override
    public void validate(Set<String> scopes) {
        if (!scopes.isEmpty()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
    }
}
