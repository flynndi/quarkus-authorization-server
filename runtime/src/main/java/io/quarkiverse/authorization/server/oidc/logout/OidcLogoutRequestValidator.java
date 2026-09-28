package io.quarkiverse.authorization.server.oidc.logout;

/**
 * Replaces logout parameter validation through CDI. Compose the default validator with
 * {@link #andThen(OidcLogoutRequestValidator)} when adding constraints to its existing checks.
 */
@FunctionalInterface
public interface OidcLogoutRequestValidator {
    void validate(OidcLogoutContext context);

    default OidcLogoutRequestValidator andThen(OidcLogoutRequestValidator next) {
        java.util.Objects.requireNonNull(next, "next cannot be null");
        return context -> {
            validate(context);
            next.validate(context);
        };
    }
}
