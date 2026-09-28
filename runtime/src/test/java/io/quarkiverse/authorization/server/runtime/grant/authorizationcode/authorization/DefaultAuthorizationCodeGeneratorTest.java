package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

class DefaultAuthorizationCodeGeneratorTest {

    @Test
    void generatesUrlSafeCodeWithRegisteredTimeToLive() {
        DefaultAuthorizationCodeGenerator generator = new DefaultAuthorizationCodeGenerator();
        OAuth2TokenContext context = context(new OAuth2TokenType(OAuth2ParameterNames.CODE));

        OAuth2AuthorizationCode first = generator.generate(context);
        OAuth2AuthorizationCode second = generator.generate(context);

        assertNotNull(first);
        assertEquals(128, first.getTokenValue().length());
        assertEquals(
                Duration.ofMinutes(3), Duration.between(first.getIssuedAt(), first.getExpiresAt()));
        assertNotEquals(first.getTokenValue(), second.getTokenValue());
    }

    @Test
    void ignoresOtherTokenTypes() {
        assertNull(
                new DefaultAuthorizationCodeGenerator()
                        .generate(context(OAuth2TokenType.ACCESS_TOKEN)));
    }

    private static OAuth2TokenContext context(OAuth2TokenType tokenType) {
        RegisteredClient registeredClient = RegisteredClient.withId("messaging-client")
                .clientId("messaging-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example.com/callback")
                .tokenSettings(
                        TokenSettings.builder()
                                .authorizationCodeTimeToLive(Duration.ofMinutes(3))
                                .build())
                .build();
        return DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .tokenType(tokenType)
                .build();
    }
}
