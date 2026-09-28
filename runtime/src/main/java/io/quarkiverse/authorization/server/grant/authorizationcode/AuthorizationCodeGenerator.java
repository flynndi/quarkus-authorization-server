package io.quarkiverse.authorization.server.grant.authorizationcode;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;

/**
 * Shared code issuance for immediate approval and consent completion; separate from access/refresh
 * generators.
 */
@FunctionalInterface
public interface AuthorizationCodeGenerator {
    OAuth2AuthorizationCode generate(OAuth2TokenContext context);
}
