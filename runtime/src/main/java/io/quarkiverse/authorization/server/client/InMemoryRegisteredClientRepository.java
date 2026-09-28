package io.quarkiverse.authorization.server.client;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import io.quarkiverse.authorization.server.runtime.util.Arguments;

/**
 * A registered client repository that stores clients in memory.
 * <p>
 * This implementation is intended for development, testing, or a small set of fixed clients. Changes are not
 * persisted across application restarts.
 * <p>
 * Both indexes use {@link ConcurrentHashMap} without an additional cross-map lock.
 */
public final class InMemoryRegisteredClientRepository implements RegisteredClientRepository {

    private final Map<String, RegisteredClient> idRegistrationMap;
    private final Map<String, RegisteredClient> clientIdRegistrationMap;

    public InMemoryRegisteredClientRepository(RegisteredClient... registrations) {
        this(Arrays.asList(registrations));
    }

    public InMemoryRegisteredClientRepository(List<RegisteredClient> registrations) {
        Objects.requireNonNull(registrations, "registrations cannot be null");
        // Quarkus can install the server before an application supplies clients.
        // Empty repositories reject lookups normally and can be populated later.
        Map<String, RegisteredClient> idRegistrationMap = new ConcurrentHashMap<>();
        Map<String, RegisteredClient> clientIdRegistrationMap = new ConcurrentHashMap<>();
        registrations.forEach(registration -> {
            Objects.requireNonNull(registration, "registration cannot be null");
            assertUniqueIdentifiers(registration, idRegistrationMap);
            idRegistrationMap.put(registration.getId(), registration);
            clientIdRegistrationMap.put(registration.getClientId(), registration);
        });
        this.idRegistrationMap = idRegistrationMap;
        this.clientIdRegistrationMap = clientIdRegistrationMap;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
        if (!this.idRegistrationMap.containsKey(registeredClient.getId())) {
            assertUniqueIdentifiers(registeredClient, this.idRegistrationMap);
        }
        this.idRegistrationMap.put(registeredClient.getId(), registeredClient);
        this.clientIdRegistrationMap.put(registeredClient.getClientId(), registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        Arguments.requireNonBlank(id, "id");
        return this.idRegistrationMap.get(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Arguments.requireNonBlank(clientId, "clientId");
        return this.clientIdRegistrationMap.get(clientId);
    }

    private static void assertUniqueIdentifiers(RegisteredClient registeredClient,
            Map<String, RegisteredClient> registrations) {
        registrations.values().forEach(registration -> {
            if (registration.getId().equals(registeredClient.getId())) {
                throw new IllegalArgumentException("Registered client must be unique. Found duplicate id: "
                        + registeredClient.getId());
            }
            if (registration.getClientId().equals(registeredClient.getClientId())) {
                throw new IllegalArgumentException("Registered client must be unique. Found duplicate clientId: "
                        + registeredClient.getClientId());
            }
            if (Arguments.hasText(registeredClient.getClientSecret())
                    && registeredClient.getClientSecret().equals(registration.getClientSecret())) {
                throw new IllegalArgumentException("Registered client must be unique. Found duplicate client secret for id: "
                        + registeredClient.getId());
            }
        });
    }
}
