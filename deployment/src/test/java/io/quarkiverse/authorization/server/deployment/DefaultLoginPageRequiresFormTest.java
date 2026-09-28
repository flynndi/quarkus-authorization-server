package io.quarkiverse.authorization.server.deployment;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class DefaultLoginPageRequiresFormTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource(new StringAsset(
                    "quarkus.authorization-server.default-login-page-enabled=true"), "application.properties"))
            .assertException(failure -> {
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    if (cause.getMessage() != null && cause.getMessage().contains("quarkus.http.auth.form.enabled=true")) {
                        return;
                    }
                }
                Assertions.fail(failure);
            });

    @Test
    void refusesToInstallALoginFormWithoutTheQuarkusAuthenticationMechanism() {
    }
}
