package io.quarkiverse.authorization.server.oidc.registration;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;

/**
 * Maps validated registration metadata to a client before secret encoding and persistence. A
 * replacement CDI bean owns its settings composition; default settings customizers are not applied
 * again by the registration service.
 */
@FunctionalInterface
public interface RegisteredClientMapper {
    RegisteredClient map(OidcClientRegistration registration);
}
