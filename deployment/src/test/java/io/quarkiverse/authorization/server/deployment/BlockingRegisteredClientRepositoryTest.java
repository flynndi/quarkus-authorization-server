package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertFalse;

import jakarta.inject.Singleton;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.http.ContentType;
import io.vertx.core.Context;

class BlockingRegisteredClientRepositoryTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClass(BlockingRegisteredClientRepository.class));

    @BeforeEach
    void resetThreadObservation() {
        BlockingRegisteredClientRepository.invokedOnEventLoop = false;
    }

    @Test
    void registeredClientLookupIsOffloadedFromEventLoop() {
        given()
                .auth().preemptive().basic("jdbc-client", "client-secret")
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .when().post("/oauth2/token")
                .then()
                .statusCode(400);

        assertFalse(BlockingRegisteredClientRepository.invokedOnEventLoop,
                "RegisteredClientRepository must not execute on the Vert.x event-loop thread");
    }

    @Singleton
    public static class BlockingRegisteredClientRepository implements RegisteredClientRepository {

        private static final RegisteredClient REGISTERED_CLIENT = RegisteredClient.withId("jdbc-client-registration")
                .clientId("jdbc-client")
                .clientName("JDBC client")
                .clientSecret("$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .build();

        static volatile boolean invokedOnEventLoop;

        @Override
        public void save(RegisteredClient registeredClient) {
            throw new UnsupportedOperationException();
        }

        @Override
        public RegisteredClient findById(String id) {
            return null;
        }

        @Override
        public RegisteredClient findByClientId(String clientId) {
            invokedOnEventLoop = Context.isOnEventLoopThread();
            return REGISTERED_CLIENT.getClientId().equals(clientId)
                    ? REGISTERED_CLIENT
                    : null;
        }
    }
}
