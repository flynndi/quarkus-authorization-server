package io.quarkiverse.authorization.server.settings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;

import org.junit.jupiter.api.Test;

class AuthorizationServerSettingsTest {

    @Test
    void usesDefaultEndpointPaths() {
        AuthorizationServerSettings settings = AuthorizationServerSettings.builder().build();

        assertNull(settings.getIssuer());
        assertEquals("/oauth2/authorize", settings.getAuthorizationEndpoint());
        assertEquals("/oauth2/device_authorization", settings.getDeviceAuthorizationEndpoint());
        assertEquals("/oauth2/device_verification", settings.getDeviceVerificationEndpoint());
        assertEquals("/oauth2/token", settings.getTokenEndpoint());
        assertEquals("/oauth2/jwks", settings.getJwkSetEndpoint());
        assertEquals("/oauth2/revoke", settings.getTokenRevocationEndpoint());
        assertEquals("/oauth2/introspect", settings.getTokenIntrospectionEndpoint());
        assertEquals("/connect/register", settings.getOidcClientRegistrationEndpoint());
        assertEquals("/userinfo", settings.getOidcUserInfoEndpoint());
        assertEquals("/connect/logout", settings.getOidcLogoutEndpoint());
    }

    @Test
    void supportsBuilderAndWithSettings() {
        AuthorizationServerSettings settings = AuthorizationServerSettings.builder()
                .issuer("https://issuer.example.com")
                .tokenEndpoint("/auth/token")
                .build();
        AuthorizationServerSettings copy = AuthorizationServerSettings.withSettings(settings.getSettings()).build();

        assertEquals(settings, copy);
        assertEquals("https://issuer.example.com", copy.getIssuer());
        assertEquals("/auth/token", copy.getTokenEndpoint());
        assertThrows(UnsupportedOperationException.class,
                () -> copy.getSettings().put("another", "value"));
        assertThrows(IllegalArgumentException.class,
                () -> AuthorizationServerSettings.withSettings(Map.of()));
    }
}
