package io.quarkiverse.authorization.server.oidc;

/**
 * Claim names defined by OpenID Connect Core for ID Tokens.
 */
public final class IdTokenClaimNames {

    public static final String ISS = "iss";
    public static final String SUB = "sub";
    public static final String AUD = "aud";
    public static final String EXP = "exp";
    public static final String IAT = "iat";
    public static final String AUTH_TIME = "auth_time";
    public static final String NONCE = "nonce";
    public static final String ACR = "acr";
    public static final String AMR = "amr";
    public static final String AZP = "azp";
    public static final String AT_HASH = "at_hash";
    public static final String C_HASH = "c_hash";

    private IdTokenClaimNames() {
    }
}
