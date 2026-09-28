package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.time.Duration;
import java.util.Set;

import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkus.test.QuarkusUnitTest;

class RegisteredClientConfigurationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addAsResource(
                            new StringAsset(
                                    """
                                            quarkus.authorization-server.clients.client-id.id=registration-id
                                            quarkus.authorization-server.clients.client-id.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                            quarkus.authorization-server.clients.client-id.authorization-grant-types=password
                                            quarkus.authorization-server.clients.client-id.scopes=message.read,message.write
                                            quarkus.authorization-server.clients.client-id.require-proof-key=true
                                            quarkus.authorization-server.clients.client-id.require-authorization-consent=true
                                            quarkus.authorization-server.clients.client-id.authorization-code-time-to-live=PT2M
                                            quarkus.authorization-server.clients.client-id.access-token-time-to-live=PT10M
                                            quarkus.authorization-server.clients.client-id.access-token-format=reference
                                            quarkus.authorization-server.clients.client-id.refresh-token-time-to-live=PT2H
                                            quarkus.authorization-server.clients.client-id.reuse-refresh-tokens=false
                                            """),
                            "application.properties"));

    @Inject
    RegisteredClientRepository registeredClientRepository;

    @Test
    void mapsRegisteredClientTokenPolicyFromConfiguration() {
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("client-id");

        org.junit.jupiter.api.Assertions.assertTrue(
                registeredClient.getClientSettings().isRequireProofKey());
        org.junit.jupiter.api.Assertions.assertTrue(
                registeredClient.getClientSettings().isRequireAuthorizationConsent());
        assertEquals(
                Duration.ofMinutes(2),
                registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive());
        assertEquals("registration-id", registeredClient.getId());
        assertEquals("registration-id", registeredClient.getClientName());
        assertEquals(Set.of("message.read", "message.write"), registeredClient.getScopes());
        assertEquals(
                Duration.ofMinutes(10),
                registeredClient.getTokenSettings().getAccessTokenTimeToLive());
        assertEquals(
                OAuth2TokenFormat.REFERENCE,
                registeredClient.getTokenSettings().getAccessTokenFormat());
        assertEquals(
                Duration.ofHours(2),
                registeredClient.getTokenSettings().getRefreshTokenTimeToLive());
        assertFalse(registeredClient.getTokenSettings().isReuseRefreshTokens());
    }
}
