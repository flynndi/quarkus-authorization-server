package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.token.DelegatingOAuth2TokenGenerator;
import io.quarkiverse.authorization.server.runtime.token.JwtGenerator;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.QuarkusUnitTest;

class OAuth2TokenGeneratorAssemblyTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest();

    @Inject
    OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Inject
    JwtGenerator jwtGenerator;

    @Test
    void installsDefaultCdiTokenGeneratorComposition() {
        assertInstanceOf(DelegatingOAuth2TokenGenerator.class, this.tokenGenerator);
        assertNotNull(this.jwtGenerator);

        RegisteredClient registeredClient = RegisteredClient.withId("client-registration")
                .clientId("messaging-client")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
        OAuth2Token token = this.tokenGenerator.generate(DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .build());

        assertInstanceOf(OAuth2RefreshToken.class, token);
    }
}
