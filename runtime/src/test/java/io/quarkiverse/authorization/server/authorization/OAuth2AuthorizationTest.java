package io.quarkiverse.authorization.server.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;

class OAuth2AuthorizationTest {

    @Test
    void buildsAuthorizationAndTokenMetadata() {
        OAuth2AccessToken accessToken = accessToken();
        Instant authorizationCodeIssuedAt = Instant.now();
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                "authorization-code",
                authorizationCodeIssuedAt,
                authorizationCodeIssuedAt.plusSeconds(300));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient())
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(Set.of("message.read"))
                .attribute("tenant", "internal")
                .authorizationCode(authorizationCode)
                .token(accessToken, metadata -> metadata.put(
                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                        Map.of("sub", "resource-owner")))
                .build();

        assertNotNull(authorization.getId());
        assertEquals("client-registration", authorization.getRegisteredClientId());
        assertEquals(authorizationCode, authorization.getAuthorizationCode().getToken());
        assertEquals(accessToken, authorization.getAccessToken().getToken());
        assertEquals(Map.of("sub", "resource-owner"), authorization.getAccessToken().getClaims());
        assertTrue(authorization.getAccessToken().isActive());
        assertThrows(UnsupportedOperationException.class,
                () -> authorization.getAttributes().put("another", "value"));

        OAuth2Authorization invalidated = OAuth2Authorization.from(authorization)
                .invalidate(accessToken)
                .build();
        assertTrue(invalidated.getAccessToken().isInvalidated());
        assertFalse(invalidated.getAccessToken().isActive());
    }

    @ParameterizedTest
    @CsvSource({ "true,true", "true,false", "false,true", "false,false" })
    void invalidatesRefreshTokenWithOptionalAssociatedTokens(boolean withAccessToken, boolean withCode) {
        Instant issuedAt = Instant.now();
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh", issuedAt, issuedAt.plusSeconds(3600));
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient())
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(Set.of("message.read"))
                .attribute("tenant", "internal")
                .token(refreshToken, metadata -> metadata.put("custom", "refresh-metadata"));
        if (withAccessToken) {
            builder.token(
                    accessToken(),
                    metadata -> metadata.put(
                            OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            Map.of("sub", "resource-owner")));
        }
        if (withCode) {
            builder.authorizationCode(
                    new OAuth2AuthorizationCode("code", issuedAt, issuedAt.plusSeconds(300)));
        }
        OAuth2Authorization original = builder.build();

        OAuth2Authorization invalidated = OAuth2Authorization.from(original).invalidate(refreshToken).build();

        assertTrue(invalidated.getRefreshToken().isInvalidated());
        assertEquals("refresh-metadata", invalidated.getRefreshToken().getMetadata("custom"));
        assertEquals(original.getId(), invalidated.getId());
        assertEquals(original.getAttributes(), invalidated.getAttributes());
        assertEquals(original.getAuthorizedScopes(), invalidated.getAuthorizedScopes());
        assertFalse(original.getRefreshToken().isInvalidated());
        if (withAccessToken) {
            assertTrue(invalidated.getAccessToken().isInvalidated());
            assertEquals(original.getAccessToken().getClaims(), invalidated.getAccessToken().getClaims());
            assertFalse(original.getAccessToken().isInvalidated());
        } else {
            assertNull(invalidated.getAccessToken());
        }
        if (withCode) {
            assertTrue(invalidated.getAuthorizationCode().isInvalidated());
            assertFalse(original.getAuthorizationCode().isInvalidated());
        } else {
            assertNull(invalidated.getAuthorizationCode());
        }
        assertEquals(invalidated, OAuth2Authorization.from(invalidated).invalidate(refreshToken).build());
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void accessTokenAndCodeInvalidationDoNotCascade(boolean invalidateAccessToken) {
        Instant issuedAt = Instant.now();
        OAuth2AuthorizationCode code = new OAuth2AuthorizationCode("code", issuedAt, issuedAt.plusSeconds(300));
        OAuth2AccessToken accessToken = accessToken();
        OAuth2Authorization original = OAuth2Authorization.withRegisteredClient(registeredClient())
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .accessToken(accessToken)
                .authorizationCode(code)
                .refreshToken(
                        new OAuth2RefreshToken(
                                "refresh", issuedAt, issuedAt.plusSeconds(3600)))
                .build();
        OAuth2Token token = invalidateAccessToken ? accessToken : code;

        OAuth2Authorization invalidated = OAuth2Authorization.from(original).invalidate(token).build();

        assertEquals(invalidateAccessToken, invalidated.getAccessToken().isInvalidated());
        assertEquals(!invalidateAccessToken, invalidated.getAuthorizationCode().isInvalidated());
        assertFalse(invalidated.getRefreshToken().isInvalidated());
        assertFalse(original.getAccessToken().isInvalidated());
        assertFalse(original.getAuthorizationCode().isInvalidated());
    }

    @Test
    void invalidatingAbsentTokenTypeDoesNotAddItOrInvalidateAssociatedTokens() {
        OAuth2Authorization original = OAuth2Authorization.withRegisteredClient(registeredClient())
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .accessToken(accessToken()).build();
        Instant issuedAt = Instant.now();
        OAuth2RefreshToken absent = new OAuth2RefreshToken("absent", issuedAt, issuedAt.plusSeconds(3600));

        assertEquals(original, OAuth2Authorization.from(original).invalidate(absent).build());
    }

    @Test
    void invalidatingNullTokenIsRejected() {
        assertThrows(NullPointerException.class,
                () -> OAuth2Authorization.withRegisteredClient(registeredClient()).invalidate(null));
    }

    @Test
    void serializesAuthorizationWithSerializableAttributes() throws Exception {
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient())
                .principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(Set.of("message.read"))
                .attribute("tenant", "internal")
                .accessToken(accessToken())
                .build();

        ByteArrayOutputStream serialized = new ByteArrayOutputStream();
        try (ObjectOutputStream output = new ObjectOutputStream(serialized)) {
            output.writeObject(authorization);
        }
        OAuth2Authorization restored;
        try (ObjectInputStream input = new ObjectInputStream(
                new ByteArrayInputStream(serialized.toByteArray()))) {
            restored = (OAuth2Authorization) input.readObject();
        }

        assertEquals("internal", restored.getAttribute("tenant"));
        assertEquals(authorization.getAccessToken(), restored.getAccessToken());
    }

    private static RegisteredClient registeredClient() {
        return RegisteredClient.withId("client-registration")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("message.read")
                .build();
    }

    private static OAuth2AccessToken accessToken() {
        Instant issuedAt = Instant.now();
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                issuedAt,
                issuedAt.plusSeconds(300),
                Set.of("message.read"));
    }
}
