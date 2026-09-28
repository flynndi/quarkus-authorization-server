package io.quarkiverse.authorization.server.deployment;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class ConflictingProtocolEndpointsTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(ClientRegistrationTestApplication::baseApplication)
            .overrideConfigKey("quarkus.authorization-server.token-endpoint", "/oauth2/authorize")
            .assertException(failure -> {
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    String message = cause.getMessage();
                    if (message != null && message.contains("Authorization Server endpoint conflict")
                            && message.contains("authorization-endpoint") && message.contains("token-endpoint")
                            && message.contains("/api/oauth2/authorize") && message.contains("POST"))
                        return;
                }
                throw new AssertionError("Expected authorization/token route conflict", failure);
            });

    @Test
    void rejectsConflictingRoutesDuringAugmentation() {
    }
}
