package io.quarkiverse.authorization.server.runtime.config;

import java.util.ArrayList;
import java.util.List;

import jakarta.enterprise.inject.Default;
import jakarta.enterprise.inject.Produces;
import jakarta.enterprise.inject.Typed;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token.OAuth2TokenExchangeTokenCustomizers;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.runtime.token.DelegatingOAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.runtime.token.DelegatingOAuth2TokenGenerator;
import io.quarkiverse.authorization.server.runtime.token.JwtGenerator;
import io.quarkiverse.authorization.server.runtime.token.OAuth2AccessTokenGenerator;
import io.quarkiverse.authorization.server.runtime.token.OAuth2RefreshTokenGenerator;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkus.arc.All;
import io.quarkus.arc.DefaultBean;

/** Composes token generators and their ordered CDI claims customizers. */
@Singleton
public final class OAuth2TokenGeneratorProducer {

    @Produces
    @Singleton
    @DefaultBean
    @Typed(JwtGenerator.class)
    JwtGenerator jwtGenerator(
            AuthorizationServerKeyManager keyManager,
            @All @Default List<OAuth2TokenCustomizer<JwtEncodingContext>> jwtCustomizers) {
        // Apply protocol claims before the application's customizations for both token formats.
        return new JwtGenerator(
                keyManager,
                new DelegatingOAuth2TokenCustomizer<>(
                        List.of(
                                OAuth2TokenExchangeTokenCustomizers.jwt(),
                                new DelegatingOAuth2TokenCustomizer<>(jwtCustomizers))));
    }

    @Produces
    @Singleton
    @DefaultBean
    OAuth2TokenGenerator<OAuth2Token> tokenGenerator(
            JwtGenerator jwtGenerator,
            @All @Default List<OAuth2TokenCustomizer<OAuth2TokenClaimsContext>> accessTokenCustomizers) {
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        List<OAuth2TokenCustomizer<OAuth2TokenClaimsContext>> tokenCustomizers = new ArrayList<>();
        tokenCustomizers.add(OAuth2TokenExchangeTokenCustomizers.accessToken());
        tokenCustomizers.addAll(accessTokenCustomizers);
        accessTokenGenerator.setAccessTokenCustomizer(
                new DelegatingOAuth2TokenCustomizer<>(tokenCustomizers));
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, new OAuth2RefreshTokenGenerator());
    }
}
