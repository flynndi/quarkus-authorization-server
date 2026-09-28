package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkus.arc.DefaultBean;

/** Generates an {@link OAuth2AuthorizationCode}. */
@Singleton
@DefaultBean
public final class DefaultAuthorizationCodeGenerator implements AuthorizationCodeGenerator {

    private static final int AUTHORIZATION_CODE_LENGTH_BYTES = 96;
    private static final SecureRandom AUTHORIZATION_CODE_RANDOM = new SecureRandom();

    @Override
    public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
        if (context.getTokenType() == null
                || !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(
                context.getRegisteredClient()
                        .getTokenSettings()
                        .getAuthorizationCodeTimeToLive());
        byte[] bytes = new byte[AUTHORIZATION_CODE_LENGTH_BYTES];
        AUTHORIZATION_CODE_RANDOM.nextBytes(bytes);
        String tokenValue = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return new OAuth2AuthorizationCode(tokenValue, issuedAt, expiresAt);
    }
}
