package io.quarkiverse.authorization.server.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTestSupport;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;

class JdbcRegisteredClientRepositoryTest {

    private JdbcRegisteredClientRepository repository;
    private JdbcDataSource dataSource;

    @BeforeEach
    void setUp() {
        this.dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:" + UUID.randomUUID()
                + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE");
        JdbcTestSupport.executeSchema(dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        this.repository = new JdbcRegisteredClientRepository(dataSource);
    }

    @Test
    void savesFindsAndUpdatesRegisteredClient() {
        Instant issuedAt = Instant.parse("2026-08-31T01:00:00Z");
        RegisteredClient registeredClient = RegisteredClient.withId("client-registration")
                .clientId("messaging-client")
                .clientIdIssuedAt(issuedAt)
                .clientSecret("{bcrypt}client-secret")
                .clientSecretExpiresAt(issuedAt.plusSeconds(3600))
                .clientName("Messaging client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .redirectUri("https://client.example.org/callback")
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .jwkSetUrl("https://client.example.org/jwks")
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.PS256)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .authorizationCodeTimeToLive(Duration.ofMinutes(3))
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .deviceCodeTimeToLive(Duration.ofMinutes(7))
                        .refreshTokenTimeToLive(Duration.ofHours(2))
                        .reuseRefreshTokens(false)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.ES256)
                        .build())
                .build();

        this.repository.save(registeredClient);

        assertEquals(registeredClient, this.repository.findById(registeredClient.getId()));
        assertEquals(registeredClient, this.repository.findByClientId(registeredClient.getClientId()));
        assertNull(this.repository.findByClientId("missing-client"));

        RegisteredClient updated = RegisteredClient.from(registeredClient)
                .clientName("Updated messaging client")
                .clientSecret("{bcrypt}updated-secret")
                .build();
        this.repository.save(updated);

        assertEquals(updated, this.repository.findById(updated.getId()));
    }

    @Test
    void enforcesUniqueClientIdAndUsesBoundParameters() {
        RegisteredClient first = passwordClient("first-registration", "shared-client");
        this.repository.save(first);

        assertThrows(IllegalArgumentException.class,
                () -> this.repository.save(passwordClient("second-registration", "shared-client")));
        assertEquals(first, this.repository.findByClientId("shared-client"));

        String clientId = "client' OR '1'='1";
        RegisteredClient quotedClient = passwordClient("quoted-registration", clientId);
        this.repository.save(quotedClient);
        assertNotNull(this.repository.findByClientId(clientId));
        assertNull(this.repository.findByClientId("client"));
    }

    @Test
    void persistsCustomSettingsWithAnExplicitCodecAcrossRepositoryInstances() {
        JdbcRegisteredClientRepository writer = new JdbcRegisteredClientRepository(this.dataSource,
                JdbcTestSupport.jsonCodec());
        RegisteredClient client = RegisteredClient.from(passwordClient("custom-codec", "custom-client"))
                .clientSettings(io.quarkiverse.authorization.server.settings.ClientSettings.builder()
                        .setting("custom", new JdbcTestSupport.CustomValue("client-data")).build())
                .tokenSettings(io.quarkiverse.authorization.server.settings.TokenSettings.builder()
                        .setting("custom", new JdbcTestSupport.CustomValue("token-data")).build())
                .build();
        writer.save(client);
        JdbcRegisteredClientRepository reader = new JdbcRegisteredClientRepository(this.dataSource,
                JdbcTestSupport.jsonCodec());
        assertEquals(client, reader.findById(client.getId()));
        assertThrows(IllegalArgumentException.class, () -> this.repository.findById(client.getId()));
        assertThrows(NullPointerException.class, () -> new JdbcRegisteredClientRepository(this.dataSource, null));
    }

    private static RegisteredClient passwordClient(String id, String clientId) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientIdIssuedAt(Instant.parse("2026-08-31T01:00:00Z"))
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("message.read")
                .build();
    }
}
