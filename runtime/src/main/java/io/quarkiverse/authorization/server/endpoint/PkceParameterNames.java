package io.quarkiverse.authorization.server.endpoint;

/**
 * Parameter names defined by Proof Key for Code Exchange (PKCE).
 */
public final class PkceParameterNames {

    public static final String CODE_CHALLENGE = "code_challenge";
    public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
    public static final String CODE_VERIFIER = "code_verifier";

    private PkceParameterNames() {
    }
}
