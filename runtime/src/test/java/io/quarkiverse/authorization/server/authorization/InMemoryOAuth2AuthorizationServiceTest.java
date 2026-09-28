package io.quarkiverse.authorization.server.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;

class InMemoryOAuth2AuthorizationServiceTest {

    @Test
    void savesFindsUpdatesAndRemovesAuthorization() {
        OAuth2Authorization authorization = authorization("authorization-1", "access-token");
        InMemoryOAuth2AuthorizationService service = new InMemoryOAuth2AuthorizationService();

        service.save(authorization);

        assertEquals(authorization, service.findById(authorization.getId()));
        assertEquals(authorization, service.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN));
        assertEquals(authorization, service.findByToken("access-token", null));
        assertEquals(authorization, service.findByToken(
                "request-state", new OAuth2TokenType(OAuth2ParameterNames.STATE)));
        assertEquals(authorization, service.findByToken(
                "authorization-code", new OAuth2TokenType(OAuth2ParameterNames.CODE)));
        assertEquals(authorization, service.findByToken(
                "user-code", new OAuth2TokenType(OAuth2ParameterNames.USER_CODE)));
        assertEquals(authorization, service.findByToken(
                "device-code", new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE)));

        OAuth2Authorization updated = OAuth2Authorization.from(authorization)
                .attribute("revision", "updated")
                .build();
        service.save(updated);
        assertEquals("updated", service.findById(updated.getId()).getAttribute("revision"));

        service.remove(updated);
        assertNull(service.findById(updated.getId()));
    }

    @Test
    void rejectsDuplicateIdentifiersAtConstruction() {
        OAuth2Authorization authorization = authorization("authorization-1", "access-token");

        assertThrows(IllegalArgumentException.class,
                () -> new InMemoryOAuth2AuthorizationService(authorization, authorization));
    }

    private static OAuth2Authorization authorization(String id, String tokenValue) {
        RegisteredClient registeredClient = RegisteredClient.withId("client-registration")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .build();
        Instant issuedAt = Instant.parse("2026-08-31T01:00:00Z");
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                tokenValue,
                issuedAt,
                issuedAt.plusSeconds(300),
                Set.of("message.read"));
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "authorization-code", issuedAt, issuedAt.plusSeconds(300));
        OAuth2UserCode userCode = new OAuth2UserCode("user-code", issuedAt, issuedAt.plusSeconds(300));
        OAuth2DeviceCode deviceCode = new OAuth2DeviceCode("device-code", issuedAt, issuedAt.plusSeconds(300));
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(id)
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(Set.of("message.read"))
                .attribute(OAuth2ParameterNames.STATE, "request-state")
                .authorizationCode(authorizationCode)
                .token(userCode)
                .token(deviceCode)
                .accessToken(accessToken)
                .build();
    }
}
