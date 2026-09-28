package io.quarkiverse.authorization.server.serialization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;

class SerializationTest {

    @Test
    void roundTripsClientSettingsAuthorizationTokensAndConsent() throws Exception {
        RegisteredClient client = RegisteredClient.withId("serialized-client")
                .clientId("fixture-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example/callback")
                .scope("message.read")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();
        Instant issuedAt = Instant.parse("2026-01-01T00:00:00Z");
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("message.read"))
                .attribute("tenant", "fixture")
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "fixture-access-token",
                        issuedAt, issuedAt.plusSeconds(300), Set.of("message.read")))
                .refreshToken(new OAuth2RefreshToken("fixture-refresh-token", issuedAt, issuedAt.plusSeconds(3600)))
                .build();
        OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId(client.getId(), "alice")
                .scope("message.read").build();

        // Exercise the current object graph; pre-preview package names are not a persisted-data contract.
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
            output.writeObject(client);
            output.writeObject(authorization);
            output.writeObject(consent);
        }
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            RegisteredClient restoredClient = (RegisteredClient) input.readObject();
            assertEquals(client.getId(), restoredClient.getId());
            assertEquals(client.getClientId(), restoredClient.getClientId());
            assertEquals(client.getClientAuthenticationMethods(), restoredClient.getClientAuthenticationMethods());
            assertEquals(client.getAuthorizationGrantTypes(), restoredClient.getAuthorizationGrantTypes());
            assertEquals(client.getScopes(), restoredClient.getScopes());
            assertTrue(restoredClient.getClientSettings().isRequireProofKey());
            assertEquals(client.getTokenSettings().getSettings(), restoredClient.getTokenSettings().getSettings());

            OAuth2Authorization restoredAuthorization = (OAuth2Authorization) input.readObject();
            assertEquals(restoredClient.getId(), restoredAuthorization.getRegisteredClientId());
            assertEquals(authorization.getPrincipalName(), restoredAuthorization.getPrincipalName());
            assertEquals(authorization.getAuthorizationGrantType(), restoredAuthorization.getAuthorizationGrantType());
            assertEquals(authorization.getAuthorizedScopes(), restoredAuthorization.getAuthorizedScopes());
            assertEquals(authorization.getAttributes(), restoredAuthorization.getAttributes());
            assertEquals(authorization.getAccessToken(), restoredAuthorization.getAccessToken());
            assertEquals(authorization.getRefreshToken(), restoredAuthorization.getRefreshToken());

            OAuth2AuthorizationConsent restoredConsent = (OAuth2AuthorizationConsent) input.readObject();
            assertEquals(consent, restoredConsent);
        }
    }
}
