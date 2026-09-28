package io.quarkiverse.authorization.server.token;

/**
 * Generates an OAuth 2.0 Token using an {@link OAuth2TokenContext}.
 * <p>
 * When generating an access token, implementations must honor the registered client's
 * {@code TokenSettings.accessTokenFormat}: {@code self-contained} means JWT and
 * {@code reference} means an opaque token. Providers persist this configured format
 * as issuance metadata and use it to validate Token Exchange input types. Custom
 * generators are trusted application code; providers do not parse or reverify their
 * output to infer its format. Return {@code null} when the requested token cannot be generated.
 */
@FunctionalInterface
public interface OAuth2TokenGenerator<T extends OAuth2Token> {

    T generate(OAuth2TokenContext context);
}
