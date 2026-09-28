package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import java.util.Set;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationRequestContext;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkus.arc.DefaultBean;

/** Default consent decision after protocol validation. */
@Singleton
@DefaultBean
public final class DefaultAuthorizationConsentPolicy implements AuthorizationConsentPolicy {
    @Override
    public boolean isConsentRequired(AuthorizationRequestContext context) {
        if (!context.getRegisteredClient().getClientSettings().isRequireAuthorizationConsent()) {
            return false;
        }
        var scopes = context.getAuthorizationRequest().getScopes();
        // Authentication alone does not require a scope consent screen.
        return !scopes.equals(Set.of(OidcScopes.OPENID))
                && (context.getAuthorizationConsent() == null
                        || !context.getAuthorizationConsent().getScopes().containsAll(scopes));
    }
}
