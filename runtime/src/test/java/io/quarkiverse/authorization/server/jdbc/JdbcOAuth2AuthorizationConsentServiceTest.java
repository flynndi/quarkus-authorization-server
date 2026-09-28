package io.quarkiverse.authorization.server.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;
import java.util.UUID;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTestSupport;

class JdbcOAuth2AuthorizationConsentServiceTest {

    private RegisteredClient registeredClient;
    private JdbcOAuth2AuthorizationConsentService authorizationConsentService;

    @BeforeEach
    void setUp() {
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:authorization-consent-" + UUID.randomUUID()
                + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        JdbcTestSupport.executeSchema(dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        JdbcTestSupport.executeSchema(dataSource, JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION);

        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(dataSource);
        this.registeredClient = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .scope("message.write")
                .build();
        registeredClientRepository.save(this.registeredClient);
        this.authorizationConsentService = new JdbcOAuth2AuthorizationConsentService(
                dataSource, registeredClientRepository);
    }

    @Test
    void insertsUpdatesFindsAndRemovesAuthorizationConsent() {
        OAuth2AuthorizationConsent authorizationConsent = OAuth2AuthorizationConsent
                .withId(this.registeredClient.getId(), "resource-owner")
                .scope("message.read")
                .build();

        this.authorizationConsentService.save(authorizationConsent);
        assertEquals(authorizationConsent, this.authorizationConsentService.findById(
                this.registeredClient.getId(), "resource-owner"));

        OAuth2AuthorizationConsent updatedConsent = OAuth2AuthorizationConsent.from(authorizationConsent)
                .scope("message.write")
                .authority("permission:messages")
                .build();
        this.authorizationConsentService.save(updatedConsent);
        OAuth2AuthorizationConsent restored = this.authorizationConsentService.findById(
                this.registeredClient.getId(), "resource-owner");
        assertEquals(Set.of("message.read", "message.write"), restored.getScopes());
        assertEquals(updatedConsent.getAuthorities(), restored.getAuthorities());

        this.authorizationConsentService.remove(updatedConsent);
        assertNull(this.authorizationConsentService.findById(
                this.registeredClient.getId(), "resource-owner"));
    }

    @Test
    void validatesRequiredArguments() {
        assertThrows(NullPointerException.class,
                () -> this.authorizationConsentService.save(null));
        assertThrows(NullPointerException.class,
                () -> this.authorizationConsentService.remove(null));
        assertThrows(IllegalArgumentException.class,
                () -> this.authorizationConsentService.findById("", "resource-owner"));
        assertThrows(IllegalArgumentException.class,
                () -> this.authorizationConsentService.findById(this.registeredClient.getId(), ""));
    }
}
