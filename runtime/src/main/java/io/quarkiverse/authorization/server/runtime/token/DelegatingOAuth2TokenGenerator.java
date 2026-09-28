package io.quarkiverse.authorization.server.runtime.token;

import java.util.Arrays;
import java.util.List;

import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;

/**
 * Delegates token generation to the first generator that returns a token.
 */
public final class DelegatingOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

    private final List<OAuth2TokenGenerator<? extends OAuth2Token>> tokenGenerators;

    @SafeVarargs
    public DelegatingOAuth2TokenGenerator(
            OAuth2TokenGenerator<? extends OAuth2Token>... tokenGenerators) {
        if (tokenGenerators == null || tokenGenerators.length == 0) {
            throw new IllegalArgumentException("tokenGenerators cannot be empty");
        }
        if (Arrays.stream(tokenGenerators).anyMatch(generator -> generator == null)) {
            throw new IllegalArgumentException("tokenGenerator cannot be null");
        }
        this.tokenGenerators = List.copyOf(Arrays.asList(tokenGenerators));
    }

    @Override
    public OAuth2Token generate(OAuth2TokenContext context) {
        for (OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator : this.tokenGenerators) {
            OAuth2Token token = tokenGenerator.generate(context);
            if (token != null) {
                return token;
            }
        }
        return null;
    }
}
