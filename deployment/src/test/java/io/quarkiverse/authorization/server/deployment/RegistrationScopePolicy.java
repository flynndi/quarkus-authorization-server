package io.quarkiverse.authorization.server.deployment;

import java.util.Set;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationContext;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;

/** Explicit scope policy for registration fixtures; absent from the strict-default application. */
@Singleton
public class RegistrationScopePolicy implements OidcClientRegistrationRequestValidator {
    @Override
    public void validate(OidcClientRegistrationContext context) {
        OidcClientRegistrationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                .andThen(OidcClientRegistrationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
                .validate(context);
        var scopes = context.request().getClientRegistration().getScopes();
        if (scopes != null
                && !Set.of("openid", "profile", "email", "message.read", "message.write")
                        .containsAll(scopes)) {
            throw new OAuth2AuthenticationException("invalid_scope");
        }
    }
}
