package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkus.runtime.Startup;
import io.quarkus.test.QuarkusUnitTest;

class InvalidRegisteredClientConfigurationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClass(RegisteredClientRepositoryConsumer.class)
                    .addAsResource(
                            new StringAsset(
                                    """
                                            quarkus.authorization-server.clients.client-id.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                            quarkus.authorization-server.clients.client-id.authorization-grant-types=authorization_code
                                            """),
                            "application.properties"))
            .assertException(throwable -> assertTrue(hasMessage(throwable, "redirectUris cannot be empty"),
                    throwable.toString()));

    @Test
    void rejectsInvalidRegisteredClientConfiguration() {
    }

    private static boolean hasMessage(Throwable throwable, String message) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current.getMessage() != null && current.getMessage().contains(message)) {
                return true;
            }
        }
        return false;
    }

    @Startup
    @ApplicationScoped
    public static class RegisteredClientRepositoryConsumer {

        @Inject
        RegisteredClientRepository registeredClientRepository;
    }
}
