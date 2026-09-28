package io.quarkiverse.authorization.server.oidc.endpoint;

/**
 * Parameter names used by OpenID Connect authentication and token responses.
 */
public final class OidcParameterNames {

    public static final String ID_TOKEN = "id_token";
    public static final String PROMPT = "prompt";
    public static final String NONCE = "nonce";

    private OidcParameterNames() {
    }
}
