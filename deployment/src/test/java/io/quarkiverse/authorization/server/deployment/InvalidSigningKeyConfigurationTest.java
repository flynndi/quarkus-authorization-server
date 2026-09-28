package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class InvalidSigningKeyConfigurationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addAsResource("privateKey.pem")
                    .addAsResource("rotatedPublicKey.pem")
                    .addAsResource(new StringAsset("""
                            quarkus.authorization-server.issuer=https://issuer.example.com
                            quarkus.authorization-server.signing.key-id=mismatched-key
                            quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                            quarkus.authorization-server.signing.public-key-location=classpath:rotatedPublicKey.pem
                            """), "application.properties"))
            .assertException(throwable -> assertTrue(hasMessage(throwable,
                    "configured private and public signing keys do not match"), throwable.toString()));

    @Test
    void rejectsMismatchedSigningKeyPair() {
    }

    private static boolean hasMessage(Throwable throwable, String message) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current.getMessage() != null && current.getMessage().contains(message)) {
                return true;
            }
        }
        return false;
    }
}
