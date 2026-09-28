package io.quarkiverse.authorization.server.runtime.client.registration;

import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.registration.ClientRegistrationScopeValidator;
import io.quarkiverse.authorization.server.client.registration.OAuth2ClientRegistrationRequest;
import io.quarkiverse.authorization.server.client.registration.OAuth2ClientRegistrationRequestValidator;
import io.quarkus.arc.DefaultBean;

/** Default OAuth registration policy; mandatory metadata checks run in the service. */
@Singleton
@DefaultBean
public final class DefaultOAuth2ClientRegistrationRequestValidator implements OAuth2ClientRegistrationRequestValidator {
    private final ClientRegistrationScopeValidator scopes;

    @Inject
    public DefaultOAuth2ClientRegistrationRequestValidator(ClientRegistrationScopeValidator scopes) {
        this.scopes = java.util.Objects.requireNonNull(scopes);
    }

    @Override
    public void validate(OAuth2ClientRegistrationRequest request) {
        this.scopes.validate(Set.copyOf(request.scopes()));
    }
}
