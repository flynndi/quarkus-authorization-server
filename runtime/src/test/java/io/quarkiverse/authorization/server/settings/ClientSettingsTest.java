package io.quarkiverse.authorization.server.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;

class ClientSettingsTest {

    @Test
    void appliesDefaultClientSettings() {
        ClientSettings clientSettings = ClientSettings.builder().build();

        assertTrue(clientSettings.isRequireProofKey());
        assertFalse(clientSettings.isRequireAuthorizationConsent());
        assertNull(clientSettings.getJwkSetUrl());
        assertNull(clientSettings.getTokenEndpointAuthenticationSigningAlgorithm());
        assertNull(clientSettings.getX509CertificateSubjectDN());
    }

    @Test
    void buildsAndCopiesSettings() {
        ClientSettings clientSettings = ClientSettings.builder()
                .requireProofKey(false)
                .requireAuthorizationConsent(true)
                .jwkSetUrl("https://client.example.com/jwks")
                .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.PS256)
                .x509CertificateSubjectDN("CN=client.example.com")
                .build();
        ClientSettings copy = ClientSettings.withSettings(clientSettings.getSettings()).build();

        assertEquals(clientSettings, copy);
        assertFalse(copy.isRequireProofKey());
        assertTrue(copy.isRequireAuthorizationConsent());
        assertEquals("https://client.example.com/jwks", copy.getJwkSetUrl());
        assertEquals(SignatureAlgorithm.PS256, copy.getTokenEndpointAuthenticationSigningAlgorithm());
        assertEquals("CN=client.example.com", copy.getX509CertificateSubjectDN());
        assertThrows(UnsupportedOperationException.class,
                () -> copy.getSettings().put("custom", true));
    }

    @Test
    void rejectsEmptySettings() {
        assertThrows(IllegalArgumentException.class, () -> ClientSettings.withSettings(Map.of()));
    }
}
