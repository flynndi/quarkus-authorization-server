package io.quarkiverse.authorization.server.jose.jws;

import io.quarkiverse.authorization.server.jose.JwaAlgorithm;

/**
 * A JSON Web Signature algorithm.
 */
public interface JwsAlgorithm extends JwaAlgorithm {
    static JwsAlgorithm from(String name) {
        SignatureAlgorithm signature = SignatureAlgorithm.from(name);
        return signature != null ? signature : MacAlgorithm.from(name);
    }
}
