package io.quarkiverse.authorization.server.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;

class InMemoryRegisteredClientRepositoryTest {

    @Test
    void findsRegisteredClientsByIdAndClientId() {
        RegisteredClient first = registeredClient("registration-1", "client-1", "secret-1");
        RegisteredClient second = registeredClient("registration-2", "client-2", "secret-2");
        InMemoryRegisteredClientRepository repository = new InMemoryRegisteredClientRepository(first, second);

        assertEquals(first, repository.findById("registration-1"));
        assertEquals(second, repository.findByClientId("client-2"));
        assertNull(repository.findById("missing"));
        assertNull(repository.findByClientId("missing"));
    }

    @Test
    void saveUpdatesBothRegistrationIndexes() {
        RegisteredClient initial = registeredClient("registration-1", "client-1", "secret-1");
        InMemoryRegisteredClientRepository repository = new InMemoryRegisteredClientRepository(initial);
        RegisteredClient updated = RegisteredClient.from(initial)
                .clientName("Updated client")
                .build();

        repository.save(updated);

        assertEquals(updated, repository.findById("registration-1"));
        assertEquals(updated, repository.findByClientId("client-1"));
    }

    @Test
    void rejectsDuplicateClientIdAndClientSecret() {
        RegisteredClient existing = registeredClient("registration-1", "client-1", "secret-1");
        InMemoryRegisteredClientRepository repository = new InMemoryRegisteredClientRepository(existing);

        assertThrows(IllegalArgumentException.class,
                () -> repository.save(registeredClient("registration-2", "client-1", "secret-2")));
        assertThrows(IllegalArgumentException.class,
                () -> repository.save(registeredClient("registration-2", "client-2", "secret-1")));
    }

    @Test
    void rejectsDuplicateRegistrationIdAtConstruction() {
        RegisteredClient first = registeredClient("registration-1", "client-1", "secret-1");
        RegisteredClient second = registeredClient("registration-1", "client-2", "secret-2");

        assertThrows(IllegalArgumentException.class,
                () -> new InMemoryRegisteredClientRepository(first, second));
    }

    @Test
    void startsEmptyAndAcceptsLaterRegistration() {
        InMemoryRegisteredClientRepository repository = new InMemoryRegisteredClientRepository();
        assertNull(repository.findByClientId("client"));
        assertNull(repository.findById("registration"));
        RegisteredClient client = registeredClient("registration", "client", "secret");
        repository.save(client);
        assertEquals(client, repository.findByClientId("client"));
        assertEquals(client, repository.findById("registration"));
    }

    private static RegisteredClient registeredClient(String id, String clientId, String clientSecret) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .build();
    }
}
