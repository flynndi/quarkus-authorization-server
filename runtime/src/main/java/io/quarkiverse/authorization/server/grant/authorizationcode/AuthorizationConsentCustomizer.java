package io.quarkiverse.authorization.server.grant.authorizationcode;

/**
 * Customizes validated consent content and the final request decision before persistence,
 * including explicit denial submissions. Invoked within the protocol worker/request scope.
 */
@FunctionalInterface
public interface AuthorizationConsentCustomizer {
    void customize(AuthorizationConsentContext context);
}
