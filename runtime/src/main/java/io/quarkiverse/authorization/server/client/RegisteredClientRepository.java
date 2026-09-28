package io.quarkiverse.authorization.server.client;

/**
 * Repository for OAuth 2.0 registered clients.
 * <p>
 * Implementations may use blocking persistence technologies such as JDBC. Callers are responsible for invoking this
 * contract from a thread where blocking is allowed.
 */
public interface RegisteredClientRepository {

    /**
     * Saves the registered client.
     * <p>
     * Sensitive values such as the client secret must be encoded before calling this method.
     *
     * @param registeredClient the registered client
     */
    void save(RegisteredClient registeredClient);

    /**
     * Finds a registered client by its internal registration identifier.
     *
     * @param id the registration identifier
     * @return the registered client, or {@code null} if not found
     */
    RegisteredClient findById(String id);

    /**
     * Finds a registered client by its OAuth 2.0 client identifier.
     *
     * @param clientId the client identifier
     * @return the registered client, or {@code null} if not found
     */
    RegisteredClient findByClientId(String clientId);
}
