package io.quarkiverse.authorization.server.grant.devicecode;

import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;

/** Generates the user-facing code paired with a Device Authorization request. */
@FunctionalInterface
public interface UserCodeGenerator {
    OAuth2UserCode generate(OAuth2TokenContext context);
}
