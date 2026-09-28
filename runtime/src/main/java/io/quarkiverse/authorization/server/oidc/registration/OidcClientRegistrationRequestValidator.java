package io.quarkiverse.authorization.server.oidc.registration;

/**
 * Replaces registration parameter validation through CDI. For scope-only changes, replace
 * {@link io.quarkiverse.authorization.server.client.registration.ClientRegistrationScopeValidator}
 * instead, preserving the default URI validation. Use
 * {@link #andThen(OidcClientRegistrationRequestValidator)} to extend a chosen base validator;
 * mandatory capability and bearer checks remain in the registration service.
 */
@FunctionalInterface
public interface OidcClientRegistrationRequestValidator {
    void validate(OidcClientRegistrationContext context);

    default OidcClientRegistrationRequestValidator andThen(
            OidcClientRegistrationRequestValidator next) {
        java.util.Objects.requireNonNull(next, "next cannot be null");
        return context -> {
            validate(context);
            next.validate(context);
        };
    }
}
