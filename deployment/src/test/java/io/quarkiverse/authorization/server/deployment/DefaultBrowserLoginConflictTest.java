package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class DefaultBrowserLoginConflictTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(LogoutTestApplication.class,
                    LogoutTestApplication.PasswordProvider.class, LogoutTestApplication.TrustedProvider.class))
            .overrideConfigKey("quarkus.http.auth.session.encryption-key", "browser-login-conflict-test-key")
            .overrideConfigKey("quarkus.authorization-server.default-login-page-enabled", "true")
            .overrideConfigKey("quarkus.http.auth.form.enabled", "true")
            .overrideConfigKey("quarkus.http.root-path", "/server")
            .overrideConfigKey("quarkus.http.auth.permission.wrong.paths", "oauth2/authorize")
            .overrideConfigKey("quarkus.http.auth.permission.wrong.methods", "GET")
            .overrideConfigKey("quarkus.http.auth.permission.wrong.policy", "permit")
            .overrideConfigKey("quarkus.http.auth.permission.wrong.auth-mechanism", "Bearer")
            .assertException(failure -> {
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    if (cause.getMessage() != null && cause.getMessage().contains("permission.\"wrong\".auth-mechanism")
                            && cause.getMessage().contains("/server/oauth2/authorize")) {
                        return;
                    }
                }
                Assertions.fail(failure);
            });

    @Test
    void rejectsAnExplicitConflictingMechanismInsteadOfSilentlySelectingOne() {
    }
}
