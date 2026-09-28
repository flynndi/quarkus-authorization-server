package io.quarkiverse.authorization.server.client.registration;

import java.util.Set;

/**
 * Scope admission policy shared by the default OAuth and OIDC registration validators.
 * Replacing this CDI bean preserves their other parameter checks. The supplied set is immutable
 * and empty when no scopes were requested. Throw an OAuth2AuthenticationException to reject it.
 */
@FunctionalInterface
public interface ClientRegistrationScopeValidator {
    void validate(Set<String> scopes);
}
