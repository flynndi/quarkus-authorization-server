package io.quarkiverse.authorization.server.client.registration;

/**
 * Application admission policy, invoked after mandatory capability and URI checks.
 * For scope-only changes, replace {@link ClientRegistrationScopeValidator} instead.
 * A full replacement owns scope admission as well.
 */
@FunctionalInterface
public interface OAuth2ClientRegistrationRequestValidator {
    void validate(OAuth2ClientRegistrationRequest request);
}
