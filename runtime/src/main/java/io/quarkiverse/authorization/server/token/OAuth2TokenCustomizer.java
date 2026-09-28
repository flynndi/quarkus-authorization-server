package io.quarkiverse.authorization.server.token;

/**
 * Customizes OAuth 2.0 Token attributes contained in a token context.
 */
@FunctionalInterface
public interface OAuth2TokenCustomizer<T extends OAuth2TokenContext> {

    void customize(T context);
}
