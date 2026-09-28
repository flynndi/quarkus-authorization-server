package io.quarkiverse.authorization.server.runtime.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

class OAuth2AuthenticationProviderUtilsTest {

    private static final Instant ISSUED_AT = Instant.now();
    private static final Set<String> SCOPES = Set.of("message.read");
    private static final Map<String, Object> CLAIMS = Map.of("sub", "resource-owner", "scope", SCOPES);

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void assemblesGeneratedTokenWithContextScopesAndIssuanceMetadata(boolean withClaims) {
        RegisteredClient client = client(withClaims ? OAuth2TokenFormat.SELF_CONTAINED : OAuth2TokenFormat.REFERENCE);
        OAuth2Authorization.Builder builder = authorization(client);
        OAuth2Token generated = generatedToken(withClaims);

        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(builder, generated, context(client));

        OAuth2Authorization.Token<OAuth2AccessToken> stored = builder.build().getAccessToken();
        assertEquals(accessToken, stored.getToken());
        assertEquals(generated.getTokenValue(), accessToken.getTokenValue());
        assertEquals(generated.getIssuedAt(), accessToken.getIssuedAt());
        assertEquals(generated.getExpiresAt(), accessToken.getExpiresAt());
        assertEquals(OAuth2AccessToken.TokenType.BEARER, accessToken.getTokenType());
        assertEquals(SCOPES, accessToken.getScopes());
        assertTrue(stored.isActive());
        assertEquals(client.getTokenSettings().getAccessTokenFormat().getValue(),
                stored.getMetadata(OAuth2TokenFormat.class.getName()));
        assertEquals(withClaims ? CLAIMS : null, stored.getClaims());
    }

    @ParameterizedTest
    @CsvSource({ "true,true", "true,false", "false,true", "false,false" })
    void replacesIssuanceMetadataWithoutMutatingOriginalAuthorization(boolean wasJwt, boolean withClaims) {
        OAuth2TokenFormat oldFormat = wasJwt ? OAuth2TokenFormat.SELF_CONTAINED : OAuth2TokenFormat.REFERENCE;
        OAuth2TokenFormat newFormat = wasJwt ? OAuth2TokenFormat.REFERENCE : OAuth2TokenFormat.SELF_CONTAINED;
        RegisteredClient client = client(newFormat);
        OAuth2AccessToken oldToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "old-token", ISSUED_AT.minusSeconds(60), ISSUED_AT.plusSeconds(300), Set.of("old.scope"));
        OAuth2Authorization original = authorization(client).token(oldToken, metadata -> {
            metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true);
            metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, Map.of("old", "claim"));
            metadata.put(OAuth2TokenFormat.class.getName(), oldFormat.getValue());
            metadata.put("custom", "retained");
        }).build();
        OAuth2Authorization.Builder builder = OAuth2Authorization.from(original);

        OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(
                builder, generatedToken(withClaims), context(client));

        OAuth2Authorization updated = builder.build();
        assertEquals(accessToken, updated.getAccessToken().getToken());
        assertEquals(SCOPES, updated.getAccessToken().getToken().getScopes());
        assertFalse(updated.getAccessToken().isInvalidated());
        assertEquals(newFormat.getValue(), updated.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
        if (withClaims) {
            assertEquals(CLAIMS, updated.getAccessToken().getClaims());
        } else {
            assertNull(updated.getAccessToken().getClaims());
            assertFalse(updated.getAccessToken().getMetadata().containsKey(OAuth2Authorization.Token.CLAIMS_METADATA_NAME));
        }
        assertEquals("retained", updated.getAccessToken().getMetadata("custom"));
        assertEquals(original.getId(), updated.getId());
        assertEquals(original.getAttributes(), updated.getAttributes());
        assertEquals(original.getAuthorizedScopes(), updated.getAuthorizedScopes());
        assertEquals(oldToken, original.getAccessToken().getToken());
        assertTrue(original.getAccessToken().isInvalidated());
        assertEquals(Map.of("old", "claim"), original.getAccessToken().getClaims());
        assertEquals(oldFormat.getValue(), original.getAccessToken().getMetadata(OAuth2TokenFormat.class.getName()));
    }

    private static RegisteredClient client(OAuth2TokenFormat format) {
        return RegisteredClient.withId("client-registration").clientId("client")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read").scope("message.write")
                .tokenSettings(TokenSettings.builder().accessTokenFormat(format).build()).build();
    }

    private static OAuth2Authorization.Builder authorization(RegisteredClient client) {
        return OAuth2Authorization.withRegisteredClient(client).principalName("resource-owner")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(Set.of("message.read", "message.write"))
                .attribute("tenant", "internal");
    }

    private static OAuth2TokenContext context(RegisteredClient client) {
        return DefaultOAuth2TokenContext.builder().registeredClient(client)
                .authorizedScopes(SCOPES).tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
    }

    private static OAuth2Token generatedToken(boolean withClaims) {
        if (withClaims) {
            return new Jwt("new-token", ISSUED_AT, ISSUED_AT.plusSeconds(300), Map.of("alg", "RS256"), CLAIMS);
        }
        // SPI token scopes do not override the scopes selected by the grant.
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "new-token", ISSUED_AT,
                ISSUED_AT.plusSeconds(300), Set.of("message.write"));
    }
}
