package io.quarkiverse.authorization.server.runtime.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceCodeExchangeRequest;
import io.quarkiverse.authorization.server.grant.refreshtoken.RefreshTokenRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OAuth2RefreshTokenGeneratorTest {

    private final OAuth2RefreshTokenGenerator generator = new OAuth2RefreshTokenGenerator();

    @Test
    void generatesUrlSafeRefreshTokenUsingConfiguredTimeToLive() {
        RegisteredClient registeredClient = registeredClient(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Duration.ofHours(2));
        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
        Instant before = Instant.now();

        OAuth2RefreshToken refreshToken = this.generator.generate(context);
        OAuth2RefreshToken anotherRefreshToken = this.generator.generate(context);

        assertNotNull(refreshToken);
        assertEquals(128, refreshToken.getTokenValue().length());
        assertTrue(refreshToken.getTokenValue().matches("[A-Za-z0-9_-]+"));
        assertTrue(!refreshToken.getIssuedAt().isBefore(before));
        assertEquals(Duration.ofHours(2), Duration.between(
                refreshToken.getIssuedAt(), refreshToken.getExpiresAt()));
        assertNotEquals(refreshToken.getTokenValue(), anotherRefreshToken.getTokenValue());
    }

    @Test
    void returnsNullForAnotherTokenType() {
        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Duration.ofMinutes(60)))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();

        assertNull(this.generator.generate(context));
    }

    @Test
    void doesNotIssueRefreshTokenToPublicAuthorizationCodeClient() {
        RegisteredClient registeredClient = registeredClient(
                ClientAuthenticationMethod.NONE, Duration.ofMinutes(60));
        SecurityIdentity clientPrincipal = clientPrincipal(registeredClient, ClientAuthenticationMethod.NONE);
        AuthorizationCodeExchangeRequest authorizationGrant = new AuthorizationCodeExchangeRequest(
                "authorization-code", clientPrincipal,
                "https://client.example.com/callback", Map.of());
        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant)
                .build();

        assertNull(this.generator.generate(context));
    }

    @Test
    void issuesRefreshTokenToConfidentialAuthorizationCodeClient() {
        RegisteredClient registeredClient = registeredClient(
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Duration.ofMinutes(60));
        SecurityIdentity clientPrincipal = clientPrincipal(
                registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        AuthorizationCodeExchangeRequest authorizationGrant = new AuthorizationCodeExchangeRequest(
                "authorization-code", clientPrincipal,
                "https://client.example.com/callback", Map.of());
        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant)
                .build();

        assertNotNull(this.generator.generate(context));
    }

    @Test
    void publicDeviceAndRefreshGenerationRequireVerifiedProof() {
        var client = registeredClient(ClientAuthenticationMethod.NONE, Duration.ofMinutes(60));
        var identity = clientPrincipal(client, ClientAuthenticationMethod.NONE);
        for (var grant : java.util.List.of(
                new DeviceCodeExchangeRequest("device-code", identity, Map.of()),
                new RefreshTokenRequest(
                        "refresh-token", identity, java.util.Set.of(), Map.of()))) {
            var context = DefaultOAuth2TokenContext.builder()
                    .registeredClient(client)
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .authorizationGrantType(grant.getGrantType())
                    .authorizationGrant(grant);
            assertNull(this.generator.generate(context.build()));
            context.put(
                    DPoPProof.class,
                    new DPoPProof("a".repeat(43), "jti", Instant.now().plusSeconds(60)));
            assertNotNull(this.generator.generate(context.build()));
        }
    }

    private static RegisteredClient registeredClient(ClientAuthenticationMethod authenticationMethod,
            Duration refreshTokenTimeToLive) {
        RegisteredClient.Builder builder = RegisteredClient.withId("client-registration")
                .clientId("messaging-client")
                .clientAuthenticationMethod(authenticationMethod)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://client.example.com/callback")
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(refreshTokenTimeToLive)
                        .build());
        if (!ClientAuthenticationMethod.NONE.equals(authenticationMethod)) {
            builder.clientSecret("client-secret");
        }
        return builder.build();
    }

    private static SecurityIdentity clientPrincipal(RegisteredClient registeredClient,
            ClientAuthenticationMethod authenticationMethod) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(registeredClient.getClientId()))
                .addAttribute(OAuth2ClientAuthenticationToken.REGISTERED_CLIENT_ATTRIBUTE, registeredClient)
                .addAttribute(OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                        authenticationMethod)
                .build();
    }
}
