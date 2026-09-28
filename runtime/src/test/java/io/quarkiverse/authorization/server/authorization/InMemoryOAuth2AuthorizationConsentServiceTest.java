package io.quarkiverse.authorization.server.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class InMemoryOAuth2AuthorizationConsentServiceTest {

    @Test
    void savesFindsUpdatesAndRemovesConsent() {
        InMemoryOAuth2AuthorizationConsentService service = new InMemoryOAuth2AuthorizationConsentService();
        OAuth2AuthorizationConsent consent = consent("message.read");
        service.save(consent);

        assertEquals(consent, service.findById("registration-id", "resource-owner"));

        OAuth2AuthorizationConsent updated = OAuth2AuthorizationConsent.from(consent)
                .scope("message.write")
                .build();
        service.save(updated);
        assertEquals(updated, service.findById("registration-id", "resource-owner"));

        service.remove(updated);
        assertNull(service.findById("registration-id", "resource-owner"));
    }

    @Test
    void rejectsDuplicateInitialConsentAndInvalidLookups() {
        OAuth2AuthorizationConsent consent = consent("message.read");

        assertThrows(IllegalArgumentException.class,
                () -> new InMemoryOAuth2AuthorizationConsentService(consent, consent));
        assertThrows(IllegalArgumentException.class,
                () -> new InMemoryOAuth2AuthorizationConsentService().findById("", "resource-owner"));
        assertThrows(IllegalArgumentException.class,
                () -> new InMemoryOAuth2AuthorizationConsentService().findById("registration-id", ""));
    }

    private static OAuth2AuthorizationConsent consent(String scope) {
        return OAuth2AuthorizationConsent.withId("registration-id", "resource-owner")
                .scope(scope)
                .build();
    }
}
