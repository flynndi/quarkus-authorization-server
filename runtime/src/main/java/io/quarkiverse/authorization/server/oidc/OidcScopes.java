package io.quarkiverse.authorization.server.oidc;

/**
 * Standard OpenID Connect scope names; a constant does not enable a claims mapper.
 */
public final class OidcScopes {

    public static final String OPENID = "openid";
    public static final String PROFILE = "profile";
    public static final String EMAIL = "email";
    public static final String ADDRESS = "address";
    public static final String PHONE = "phone";

    private OidcScopes() {
    }
}
