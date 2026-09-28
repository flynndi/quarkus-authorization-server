package io.quarkiverse.authorization.server.jose.jws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;

import org.junit.jupiter.api.Test;

class SignatureAlgorithmTest {

    @Test
    void exposesSupportedSignatureAlgorithmNames() {
        assertEquals(List.of("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"),
                java.util.Arrays.stream(SignatureAlgorithm.values()).map(SignatureAlgorithm::getName).toList());
        assertEquals(SignatureAlgorithm.PS256, SignatureAlgorithm.from("PS256"));
        assertNull(SignatureAlgorithm.from("EdDSA"));
    }
}
