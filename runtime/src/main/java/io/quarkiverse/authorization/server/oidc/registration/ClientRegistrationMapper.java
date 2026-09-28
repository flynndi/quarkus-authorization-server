package io.quarkiverse.authorization.server.oidc.registration;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;

/**
 * Maps a client to registration metadata. Registration and configuration reads share this CDI
 * strategy; the service supplies registration management URLs and access-token fields separately.
 */
@FunctionalInterface
public interface ClientRegistrationMapper {
    OidcClientRegistration map(RegisteredClient client);
}
