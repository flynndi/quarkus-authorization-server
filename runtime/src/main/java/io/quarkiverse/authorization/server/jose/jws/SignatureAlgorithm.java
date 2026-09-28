package io.quarkiverse.authorization.server.jose.jws;

/**
 * Asymmetric signature algorithms supported by the authorization server.
 */
public enum SignatureAlgorithm implements JwsAlgorithm {

    RS256(JwsAlgorithms.RS256),
    RS384(JwsAlgorithms.RS384),
    RS512(JwsAlgorithms.RS512),
    ES256(JwsAlgorithms.ES256),
    ES384(JwsAlgorithms.ES384),
    ES512(JwsAlgorithms.ES512),
    PS256(JwsAlgorithms.PS256),
    PS384(JwsAlgorithms.PS384),
    PS512(JwsAlgorithms.PS512);

    private final String name;

    SignatureAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }

    public static SignatureAlgorithm from(String name) {
        for (SignatureAlgorithm value : values()) {
            if (value.getName().equals(name)) {
                return value;
            }
        }
        return null;
    }
}
