package io.quarkiverse.authorization.server.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;

class RegisteredClientTest {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { " ", "\t\n", "\u2003" })
    void rejectsBlankIdentifiersAtTheModelBoundary(String identifier) {
        assertThrows(IllegalArgumentException.class, () -> RegisteredClient.withId(identifier));
        assertThrows(IllegalArgumentException.class,
                () -> RegisteredClient.withId("registration-id").clientId(identifier)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build());
    }

    @Test
    void preservesNonBlankIdentifiersWithoutTrimming() {
        RegisteredClient client = RegisteredClient.withId(" registration-id ").clientId(" client-id ")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();

        assertEquals(" registration-id ", client.getId());
        assertEquals(" client-id ", client.getClientId());
    }

    @Test
    void appliesClientDefaultsWithoutRequiringAClientSecretAtBuildTime() {
        RegisteredClient registeredClient = RegisteredClient.withId("registration-id")
                .clientId("client-id")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .build();

        assertEquals("registration-id", registeredClient.getClientName());
        assertEquals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                registeredClient.getClientAuthenticationMethods());
        assertNull(registeredClient.getClientSecret());
        assertTrue(registeredClient.getClientSettings().isRequireProofKey());
        assertFalse(registeredClient.getClientSettings().isRequireAuthorizationConsent());
        assertEquals(Duration.ofMinutes(5), registeredClient.getTokenSettings().getAccessTokenTimeToLive());
    }

    @Test
    void storesImmutablePasswordGrantAndTokenPolicy() {
        RegisteredClient registeredClient = RegisteredClient.withId("registration-id")
                .clientId("client-id")
                .clientSecret("sensitive-client-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10)).build())
                .build();

        assertEquals(Set.of("message.read", "message.write"), registeredClient.getScopes());
        assertEquals(Duration.ofMinutes(10), registeredClient.getTokenSettings().getAccessTokenTimeToLive());
        assertThrows(UnsupportedOperationException.class, () -> registeredClient.getScopes().add("message.delete"));
        assertFalse(registeredClient.toString().contains("sensitive-client-secret"));

        RegisteredClient copiedClient = RegisteredClient.from(registeredClient).clientName("Copied client").build();
        assertEquals(registeredClient.getScopes(), copiedClient.getScopes());
        assertEquals(registeredClient.getClientSettings(), copiedClient.getClientSettings());
        assertEquals(registeredClient.getTokenSettings(), copiedClient.getTokenSettings());
    }

    @Test
    void requiresProofKeyAndConsentByDefaultForPublicAuthorizationCodeClient() {
        RegisteredClient registeredClient = RegisteredClient.withId("registration-id")
                .clientId("client-id")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .build();

        assertTrue(registeredClient.getClientSettings().isRequireProofKey());
        assertTrue(registeredClient.getClientSettings().isRequireAuthorizationConsent());
    }

    @Test
    void requiresRedirectUriForAuthorizationCodeGrant() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> RegisteredClient.withId("registration-id")
                        .clientId("client-id")
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .build());

        assertEquals("redirectUris cannot be empty", exception.getMessage());
    }

    @Test
    void validatesScopeCharacters() {
        RegisteredClient registeredClient = RegisteredClient.withId("registration-id")
                .clientId("client-id")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("!#$%&'()*+,-./:;<=>?@[]^_`{|}~")
                .build();

        assertEquals(Set.of("!#$%&'()*+,-./:;<=>?@[]^_`{|}~"), registeredClient.getScopes());
        assertThrows(IllegalArgumentException.class, () -> passwordClientWithScope("message read"));
        assertThrows(IllegalArgumentException.class, () -> passwordClientWithScope("message\"read"));
        assertThrows(IllegalArgumentException.class, () -> passwordClientWithScope("message\\read"));
    }

    @Test
    void validatesRedirectUriSyntaxAndFragment() {
        RegisteredClient registeredClient = RegisteredClient.withId("registration-id")
                .clientId("client-id")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .build();

        assertEquals(Set.of("https://client.example.com/callback"), registeredClient.getRedirectUris());
        assertThrows(IllegalArgumentException.class,
                () -> authorizationCodeClientWithRedirectUri("https://client.example.com/callback#fragment"));
        assertThrows(IllegalArgumentException.class,
                () -> authorizationCodeClientWithRedirectUri("https://client.example.com/callback invalid"));
    }

    private static RegisteredClient passwordClientWithScope(String scope) {
        return RegisteredClient.withId("registration-id")
                .clientId("client-id")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope(scope)
                .build();
    }

    private static RegisteredClient authorizationCodeClientWithRedirectUri(String redirectUri) {
        return RegisteredClient.withId("registration-id")
                .clientId("client-id")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .build();
    }
}
