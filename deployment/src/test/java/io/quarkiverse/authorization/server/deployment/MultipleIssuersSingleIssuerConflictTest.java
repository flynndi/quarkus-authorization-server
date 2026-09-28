package io.quarkiverse.authorization.server.deployment;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class MultipleIssuersSingleIssuerConflictTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset("""
                    quarkus.authorization-server.multiple-issuers-allowed=true
                    quarkus.authorization-server.issuer=https://server.example
                    quarkus.authorization-server.issuers.alpha=https://server.example/alpha
                    """), "application.properties"))
            .assertException(failure -> {
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    if (cause.getMessage() != null && cause.getMessage().contains("no single issuer setting"))
                        return;
                }
                throw new AssertionError("Expected issuer configuration rejection", failure);
            });

    @Test
    void rejectsInvalidConfigurationAtStartup() {
    }
}
