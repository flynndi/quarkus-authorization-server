package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class InvalidAuthorizationServerEndpointConfigurationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset(
                    "quarkus.authorization-server.token-endpoint=https://example.com/oauth2/token"),
                    "application.properties"))
            .assertException(throwable -> assertTrue(
                    hasMessage(throwable, "Authorization Server endpoint must be an absolute path"),
                    throwable.toString()));

    @Test
    void rejectsEndpointUrlInsteadOfApplicationPath() {
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
