package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class ConflictingRegistrationEndpointsTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(ClientRegistrationTestApplication::baseApplication)
            .overrideConfigKey("quarkus.authorization-server.client-registration.enabled", "true")
            .overrideConfigKey("quarkus.authorization-server.client-registration-endpoint", "/clients")
            .assertException(failure -> {
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    if (cause.getMessage() != null
                            && cause.getMessage().contains("Authorization Server endpoint conflict")
                            && cause.getMessage().contains("quarkus.authorization-server.client-registration-endpoint")
                            && cause.getMessage().contains("quarkus.authorization-server.oidc-client-registration-endpoint")
                            && cause.getMessage().contains("/api/clients")
                            && cause.getMessage().contains("POST"))
                        return;
                }
                throw new AssertionError("Expected registration route conflict", failure);
            });

    @Test
    void cannotExposeOpenOAuthRegistrationAtTheProtectedOidcPath() {
    }
}
