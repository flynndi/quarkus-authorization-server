package io.quarkiverse.authorization.server.jose.jws;

/** HMAC algorithms for client assertions; these are not authorization-server signing keys. */
public enum MacAlgorithm implements JwsAlgorithm {
    HS256(JwsAlgorithms.HS256),
    HS384(JwsAlgorithms.HS384),
    HS512(JwsAlgorithms.HS512);

    private final String name;

    MacAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }

    public static MacAlgorithm from(String name) {
        for (MacAlgorithm algorithm : MacAlgorithm.values()) {
            if (algorithm.getName().equals(name))
                return algorithm;
        }
        return null;
    }
}
