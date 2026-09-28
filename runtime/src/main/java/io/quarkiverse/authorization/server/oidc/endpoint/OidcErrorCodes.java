package io.quarkiverse.authorization.server.oidc.endpoint;

/** OIDC authentication errors returned when an authorization request cannot complete silently. */
public final class OidcErrorCodes {
    public static final String LOGIN_REQUIRED = "login_required";
    public static final String CONSENT_REQUIRED = "consent_required";

    private OidcErrorCodes() {
    }
}
