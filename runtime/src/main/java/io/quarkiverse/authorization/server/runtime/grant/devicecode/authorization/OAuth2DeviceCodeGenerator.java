package io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceCodeGenerator;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkus.arc.DefaultBean;

/** Default OAuth2DeviceCodeGenerator policy. Instances contain no per-request state. */
@Singleton
@DefaultBean
public final class OAuth2DeviceCodeGenerator implements DeviceCodeGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public OAuth2DeviceCode generate(OAuth2TokenContext context) {
        if (context.getTokenType() == null
                || !OAuth2ParameterNames.DEVICE_CODE.equals(context.getTokenType().getValue())) {
            return null;
        }
        byte[] bytes = new byte[96];
        RANDOM.nextBytes(bytes);
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(
                context.getRegisteredClient().getTokenSettings().getDeviceCodeTimeToLive());
        return new OAuth2DeviceCode(
                Base64.getUrlEncoder().withoutPadding().encodeToString(bytes), issuedAt, expiresAt);
    }
}
