package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkus.test.QuarkusUnitTest;

class AuthorizationServerStorageIsolationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest().withEmptyApplication();

    @Inject
    RegisteredClientRepository clients;

    @Inject
    OAuth2AuthorizationService authorizations;

    @Inject
    OAuth2AuthorizationConsentService consents;

    @Test
    void startsWithInMemoryStorageWithoutAgroalOrJta() {
        assertInstanceOf(InMemoryRegisteredClientRepository.class, this.clients);
        assertInstanceOf(InMemoryOAuth2AuthorizationService.class, this.authorizations);
        assertInstanceOf(InMemoryOAuth2AuthorizationConsentService.class, this.consents);

        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        for (String className : new String[] {
                "io.agroal.api.AgroalDataSource",
                "io.quarkus.narayana.jta.QuarkusTransaction"
        }) {
            assertThrows(ClassNotFoundException.class, () -> Class.forName(className, false, classLoader), className);
        }
        for (String schema : new String[] {
                "oauth2-registered-client-schema.sql",
                "oauth2-authorization-schema.sql",
                "oauth2-authorization-consent-schema.sql"
        }) {
            assertNotNull(classLoader.getResource("META-INF/quarkus-authorization-server/schema/" + schema), schema);
        }
    }
}
