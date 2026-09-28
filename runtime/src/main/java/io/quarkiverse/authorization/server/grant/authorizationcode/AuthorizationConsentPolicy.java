package io.quarkiverse.authorization.server.grant.authorizationcode;

/** Application extension point invoked within the protocol worker/request scope. */
@FunctionalInterface
public interface AuthorizationConsentPolicy {
    boolean isConsentRequired(AuthorizationRequestContext context);
}
