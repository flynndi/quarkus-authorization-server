package io.quarkiverse.authorization.server.jose.jws;

/**
 * JSON Web Signature algorithm names defined by the JWA specification.
 */
public final class JwsAlgorithms {

    public static final String HS256 = "HS256";
    public static final String HS384 = "HS384";
    public static final String HS512 = "HS512";
    public static final String RS256 = "RS256";
    public static final String RS384 = "RS384";
    public static final String RS512 = "RS512";
    public static final String ES256 = "ES256";
    public static final String ES384 = "ES384";
    public static final String ES512 = "ES512";
    public static final String PS256 = "PS256";
    public static final String PS384 = "PS384";
    public static final String PS512 = "PS512";

    private JwsAlgorithms() {
    }
}
