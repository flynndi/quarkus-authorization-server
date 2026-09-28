package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class InvalidIssuerConfigurationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset(
                    "quarkus.authorization-server.issuer=https://issuer.example.com?tenant=one"),
                    "application.properties"))
            .assertException(throwable -> assertTrue(hasMessage(throwable,
                    "issuer must be an absolute HTTP(S) URL without query or fragment"), throwable.toString()));

    @Test
    void rejectsInvalidIssuer() {
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
