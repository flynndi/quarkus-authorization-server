package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import java.security.SecureRandom;
import java.time.Instant;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.UserCodeGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.arc.DefaultBean;

/** Default OAuth2UserCodeGenerator policy. Instances contain no per-request state. */
@Singleton
@DefaultBean
public final class OAuth2UserCodeGenerator implements UserCodeGenerator {

    private static final char[] VALID_CHARS = {
            'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M',
            'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Z'
    };
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public OAuth2UserCode generate(OAuth2TokenContext context) {
        if (context.getTokenType() == null
                || !OAuth2ParameterNames.USER_CODE.equals(context.getTokenType().getValue())) {
            return null;
        }
        byte[] bytes = new byte[8];
        RANDOM.nextBytes(bytes);
        StringBuilder userCode = new StringBuilder(9);
        for (byte value : bytes) {
            userCode.append(VALID_CHARS[Math.abs(value % VALID_CHARS.length)]);
        }
        userCode.insert(4, '-');
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(
                context.getRegisteredClient().getTokenSettings().getDeviceCodeTimeToLive());
        return new OAuth2UserCode(userCode.toString(), issuedAt, expiresAt);
    }
}
