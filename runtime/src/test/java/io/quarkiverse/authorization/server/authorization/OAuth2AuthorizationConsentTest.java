package io.quarkiverse.authorization.server.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;

import org.junit.jupiter.api.Test;

class OAuth2AuthorizationConsentTest {

    @Test
    void storesScopesAsAuthoritiesAndCopiesConsent() {
        OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent
                .withId("registration-id", "resource-owner")
                .scope("message.read")
                .authority("ROLE_APPROVER")
                .build();
        OAuth2AuthorizationConsent copy = OAuth2AuthorizationConsent.from(consent)
                .scope("message.write")
                .build();

        assertEquals(Set.of("SCOPE_message.read", "ROLE_APPROVER"), consent.getAuthorities());
        assertEquals(Set.of("message.read"), consent.getScopes());
        assertEquals(Set.of("message.read", "message.write"), copy.getScopes());
        assertThrows(UnsupportedOperationException.class,
                () -> consent.getAuthorities().add("ROLE_ADMIN"));
    }

    @Test
    void validatesIdentifiersAndAuthorities() {
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2AuthorizationConsent.withId("", "resource-owner"));
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2AuthorizationConsent.withId("registration-id", ""));
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2AuthorizationConsent.withId("registration-id", "resource-owner").build());
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2AuthorizationConsent.withId("registration-id", "resource-owner").scope(""));
    }
}
