package io.quarkiverse.authorization.server.deployment;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class MultipleIssuersEmptyConfigurationTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset("""
                    quarkus.authorization-server.multiple-issuers-allowed=true
                    """), "application.properties"))
            .assertException(failure -> {
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    if (cause.getMessage() != null && cause.getMessage().contains("nonempty issuers map"))
                        return;
                }
                throw new AssertionError("Expected issuer configuration rejection", failure);
            });

    @Test
    void rejectsInvalidConfigurationAtStartup() {
    }
}
