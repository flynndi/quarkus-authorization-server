package io.quarkiverse.authorization.server.runtime.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.ClaimAccessor;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsSet;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OAuth2AccessTokenGeneratorTest {
    private final OAuth2AccessTokenGenerator generator = new OAuth2AccessTokenGenerator();

    @Test
    void generatesReferenceTokenAndAuthorizationClaims() {
        OAuth2TokenContext context = context(OAuth2TokenFormat.REFERENCE, Set.of("message.read"));
        Instant before = Instant.now();
        OAuth2AccessToken token = this.generator.generate(context);
        OAuth2AccessToken second = this.generator.generate(context);

        assertNotNull(token);
        assertEquals(128, token.getTokenValue().length());
        assertTrue(token.getTokenValue().matches("[A-Za-z0-9_-]+"));
        assertEquals(1, token.getTokenValue().split("\\.", -1).length);
        assertNotEquals(token.getTokenValue(), second.getTokenValue());
        assertEquals(Duration.ofMinutes(7), Duration.between(token.getIssuedAt(), token.getExpiresAt()));
        assertFalse(token.getIssuedAt().isBefore(before));
        ClaimAccessor claims = assertInstanceOf(ClaimAccessor.class, token);
        assertEquals("https://issuer.example", claims.getClaim("iss"));
        assertEquals("machine-client", claims.getClaim("sub"));
        assertEquals(List.of("machine-client"), claims.getClaim("aud"));
        assertEquals(token.getIssuedAt(), claims.getClaim("iat"));
        assertEquals(token.getIssuedAt(), claims.getClaim("nbf"));
        assertEquals(token.getExpiresAt(), claims.getClaim("exp"));
        assertNotNull(claims.getClaim("jti"));
        assertEquals(Set.of("message.read"), claims.getClaim("scope"));
    }

    @Test
    void customizerReceivesFullContextAndCanReplaceClaims() {
        this.generator.setAccessTokenCustomizer(context -> {
            assertEquals("machine-client", context.getRegisteredClient().getClientId());
            assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, context.getAuthorizationGrantType());
            assertEquals(Set.of("message.read"), context.getAuthorizedScopes());
            context.getClaims().claims(claims -> {
                claims.remove("jti");
                claims.put("custom", "value");
            });
        });
        ClaimAccessor token = assertInstanceOf(ClaimAccessor.class,
                this.generator.generate(context(OAuth2TokenFormat.REFERENCE, Set.of("message.read"))));
        assertEquals("value", token.getClaim("custom"));
        assertFalse(token.hasClaim("jti"));
    }

    @Test
    void omitsScopeAndIssuerWhenAbsent() {
        OAuth2TokenContext context = context(OAuth2TokenFormat.REFERENCE, Set.of(), null);
        ClaimAccessor token = assertInstanceOf(ClaimAccessor.class, this.generator.generate(context));
        assertFalse(token.hasClaim("scope"));
        assertFalse(token.hasClaim("iss"));
    }

    @Test
    void onlyHandlesReferenceAccessTokens() {
        assertNull(this.generator.generate(context(OAuth2TokenFormat.SELF_CONTAINED, Set.of())));
        OAuth2TokenContext refresh = DefaultOAuth2TokenContext.builder()
                .registeredClient(client(OAuth2TokenFormat.REFERENCE)).tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
        assertNull(this.generator.generate(refresh));
        assertThrows(NullPointerException.class, () -> this.generator.setAccessTokenCustomizer(null));
    }

    @Test
    void claimsSetAndContextAreDefensive() {
        OAuth2TokenClaimsSet set = OAuth2TokenClaimsSet.builder().subject("subject")
                .claims(claims -> claims.put("custom", true)).build();
        assertEquals(true, set.getClaim("custom"));
        assertThrows(UnsupportedOperationException.class, () -> set.getClaims().put("another", true));
        assertThrows(IllegalArgumentException.class, () -> OAuth2TokenClaimsSet.builder().build());
        assertThrows(IllegalArgumentException.class, () -> OAuth2TokenClaimsSet.builder().claim(" ", "value"));
    }

    private static OAuth2TokenContext context(OAuth2TokenFormat format, Set<String> scopes) {
        return context(format, scopes, "https://issuer.example");
    }

    private static OAuth2TokenContext context(OAuth2TokenFormat format, Set<String> scopes, String issuer) {
        RegisteredClient client = client(format);
        var principal = QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(client.getClientId()))
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, client).build();
        var builder = DefaultOAuth2TokenContext.builder().registeredClient(client).principal(principal)
                .authorizedScopes(scopes).tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).authorizationGrant(Map.of());
        if (issuer != null) {
            builder.authorizationServerContext(new DefaultAuthorizationServerContext(
                    AuthorizationServerSettings.builder().issuer(issuer).build()));
        }
        return builder.build();
    }

    private static RegisteredClient client(OAuth2TokenFormat format) {
        return RegisteredClient.withId("machine-registration").clientId("machine-client")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("message.read")
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(7))
                        .accessTokenFormat(format).build())
                .build();
    }
}
