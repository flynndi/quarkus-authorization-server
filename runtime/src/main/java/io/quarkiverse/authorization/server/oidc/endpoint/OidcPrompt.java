package io.quarkiverse.authorization.server.oidc.endpoint;

/** OIDC interaction suppression; other prompt behaviors are not implemented by this server. */
public final class OidcPrompt {
    public static final String NONE = "none";

    private OidcPrompt() {
    }
}
