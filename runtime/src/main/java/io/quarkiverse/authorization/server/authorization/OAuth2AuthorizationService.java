package io.quarkiverse.authorization.server.authorization;

import io.quarkiverse.authorization.server.token.OAuth2TokenType;

/**
 * Manages OAuth 2.0 authorizations.
 */
public interface OAuth2AuthorizationService {

    void save(OAuth2Authorization authorization);

    void remove(OAuth2Authorization authorization);

    OAuth2Authorization findById(String id);

    OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType);
}
